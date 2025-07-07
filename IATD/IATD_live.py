import pandas as pd
import xgboost as xgb
import time
import numpy as np
import json
import os
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import seaborn as sns
import matplotlib.pyplot as plt
from extract_attributes import process_packet
from extract_attributes import ATTRIBUTES
import subprocess
from dateutil import parser


#Tipo de classificação
classification_type = 'binary'
#classification_type = 'multiclass'

#interface de rede
interface = 'Wi-fi'


###################################################### FILE PATHS ######################################################
# Caminho do modelo
model_name = 'xgb_full'
#model_name = 'xgb_sampled'
model_path = classification_type + '/models/' + model_name + '.json'

#Caminho do metadata
metadata_dir = classification_type
metadata_path = os.path.join(metadata_dir, 'metadata.json')

# Caminho da pasta onde os arquivos serão salvos, cria se não existir
output_dir = "output_graphs_and_reports_" + classification_type
os.makedirs(output_dir, exist_ok=True)


#################################################### LOAD METADATA #####################################################
with open(metadata_path, "r") as f:
    metadata = json.load(f)

target_column = metadata["target"]["name"]  #label
cat_dtypes = metadata["features"]["categorical_cols"]  #{'protocol': 'int8'} Tipo de dado da coluna protocolo
num_dtypes = metadata["features"]["numerical_cols"]  #Tipos de dado das colunas numéricas (ttl, ip_len, src_port, dst_port, flags de protocolos...)
category_mappings = metadata["features"]["category_mappings"]  #lista número-protocolo

for col, mapping in category_mappings.items():
    category_mappings[col] = {v: int(k) for k, v in mapping.items()}
    #lista protocolo-número

index_to_label = {int(k): v for k, v in metadata["target"]["index_to_label"].items()}  #{0: 'benign', 1: 'malign'}
label_to_index = {str(k): int(v) for k, v in metadata["target"]["label_to_index"].items()}  #{'benign': 0, 'malign': 1}


##################################################### LOAD MODEL #######################################################
model = xgb.Booster()
model.load_model(model_path)
model_features = model.feature_names
print(f"✔ Model load from: {model_path}")


#################################################### CAPTURE PACKETS ###################################################
print('Capturing packets...')

# dataframe para salvar pacotes processados
samples_df = pd.DataFrame(columns=ATTRIBUTES)

# comando de captura
command = [
    'tshark',
    '-i', interface,
    '-l',
    '-T', 'ek'  # JSON por linha
]

# captura pacotes, processa e salva
try:
    # processo filho
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,  # direciona a saída do comando ao processo
        stderr=subprocess.DEVNULL,  # ignora erros
        text=True  #  saída em formato string (em vez de bytes)
    )
    buffer = ""

    for linha in process.stdout:
        if linha.strip().startswith('{"index":'):
            continue
        buffer += linha
        try:
            packet = json.loads(buffer)  # converte string JSON em dicionário
            packet_count += 1
            new_sample_df = process_packet(packet)
            samples_df = pd.concat([samples_df, new_sample_df[samples_df.columns]], ignore_index=True)
            buffer = ""

        except json.JSONDecodeError:
            # ainda não tem JSON completo, continua lendo
            continue

except KeyboardInterrupt:
    print("Captura interrompida pelo usuário.")

except Exception as e:
    print(f"Erro durante a execução: {e}")


######################################## ADJUST THE SAMPLES BASED ON METADATA ##########################################
for col, mapping in category_mappings.items():
    if col in samples_df.columns:  # substitui protocolo por número
        samples_df[col] = samples_df[col].map(mapping)

for col, dtype in {**cat_dtypes, **num_dtypes}.items():
    if col in samples_df.columns:  # ajusta tipo dos dados das colunas numéricas
        samples_df[col] = pd.to_numeric(samples_df[col], errors='coerce').fillna(0).astype(dtype)

# completa colunas ausentes em relação aos atributos do modelo com valor 0, se necessário
for col in model_features:
    if col not in samples_df.columns:
        new_sample[col] = 0

# copia amostras completas
samples_df_copy = samples_df.copy()

# filtra atributos no padrão do modelo e converte a amostra para dmatrix
samples_df = samples_df[model_features]
dmatrix = xgb.DMatrix(samples_df, feature_names=model.feature_names, enable_categorical=True)


#################################################### DO PREDICTIONS ####################################################
# faz as predições, contabilizando o tempo
start_time = time.time()
y_pred_probs = model.predict(dmatrix)
latency = time.time() - start_time
y_pred = (y_pred_probs > 0.5).astype(int)

# resumo das amostras testadas
results_df = samples_df_copy[["timestamp", "src_ip", "dst_ip", "is_attack"]].copy()
results_df["predicted"] = y_pred
results_df["is_attack"] = results_df["is_attack"].astype(int)
results_df["predicted"] = results_df["predicted"].astype(int)

with pd.option_context(
        'display.max_rows', None,
        'display.max_columns', None,
        'display.width', None,
        'display.max_colwidth', None
):
    print(results_df)


################################################### REPORT AND LATENCY #################################################
#Gera relatório
labels = [0, 1]
target_names = label_to_index.keys()

clf_report = classification_report(results_df["is_attack"], results_df["predicted"],
                                   labels=labels, target_names=target_names, digits=6, zero_division=0)
#Exibe relatório
print("-" * 25, classification_type, "-" * 25)
print(clf_report)
print("-" * 60)

#Exibe latência
print(f"⏱️ Total latency: {latency:.4f} seconds")
avg_latency = latency / len(samples_df)
print(f"📏 Average latency per sample: {avg_latency * 1000:.4f} ms")

report_results = {
    "report": clf_report,
    "total_latency": latency,
    "avg_latency_ms": avg_latency * 1000
}

with open(os.path.join(output_dir,"report_" + classification_type + "_" + model_name + ".txt"), "w") as f:
  f.write(f"Modelo: {model_name}\n")
  f.write(f"{report_results['report']}\n")
  f.write(f"Total latency: {report_results['total_latency']:.4f} seconds\n")
  f.write(f"Average latency per sample: {report_results['avg_latency_ms']:.4f} ms\n")
  f.write("-" * 80 + "\n")


################################################## MATRIZ DE CONFUSÃO ##################################################
# Rótulos
labels = [0, 1]
labels_cat = ["Benign", "Malign"]

# Gerar a matriz
cm = confusion_matrix(results_df["is_attack"], results_df["predicted"], labels=labels)
cm = np.array(cm)

# Plot com seaborn
plt.figure(figsize=(8, 6))
ax = sns.heatmap(cm,
                annot=True,
                fmt='d',
                cmap='Blues',
                xticklabels=labels_cat,
                yticklabels=labels_cat,
                annot_kws={"size": 14})

# Títulos e rótulos traduzidos
plt.title(f"Confusion matrix - {model_name} - {classification_type}", fontsize=16)
plt.xlabel("Predicted class", fontsize=16)
plt.ylabel("True class", fontsize=16)

# Ajustar ticks
plt.xticks(fontsize=14, rotation=45, ha='right')
plt.yticks(fontsize=14, rotation=0)

plt.tight_layout()
plt.savefig(os.path.join(output_dir, f"confusion_matrix_{classification_type}_{model_name}.pdf"), dpi=300)
plt.savefig(os.path.join(output_dir, f"confusion_matrix_{classification_type}_{model_name}.png"), dpi=300)


#Ajusta tamanho da fonte dos gráficos
plt.rcParams.update({'font.size': 16})

# Extrai métricas
report_dict = classification_report(results_df["is_attack"], results_df["predicted"], output_dict=True, zero_division=0)
precision = report_dict["macro avg"]["precision"]
recall = report_dict["macro avg"]["recall"]
f1_score = report_dict["macro avg"]["f1-score"]
accuracy = report_dict["accuracy"]
avg_latency_us = avg_latency * 1000000
model_metrics = [precision, recall, f1_score, accuracy, avg_latency_us]

# Converter para DataFrame longo
metric_names = ["Precision", "Recall", "F1-Score", "Accuracy", "avg_latency_us"]
data = []
for i, metric in enumerate(metric_names):
    data.append({
        "Model": model_name,
        "Metric": metric,
        "Value": model_metrics[i]
    })

avg_metrics_df = pd.DataFrame(data)
avg_metrics_df.to_csv(output_dir + "\\avg_metrics_" + classification_type + "_" + model_name + ".csv", index=False)
