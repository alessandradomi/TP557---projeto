import pandas as pd
import numpy as np
import os
from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
import seaborn as sns
import matplotlib.pyplot as plt
'''
model_names = [
    "xgb_full",
    "xgb_sampled",
    "xgb_reduced",
    "xgb_filtered",
    "xgb_best_latency",
    "xgb_best_f1_score",
    "xgb_best_balance"
]
'''
model_names = [
    "xgb_full",
    "xgb_sampled",
    "xgb_reduced",
    "xgb_filtered"
]

label_to_index = {'benign': 0, 'malign': 1}
models_metrics_df = pd.DataFrame()

attacks = {
    '0': 'all',
    '1': 'scan_A',
    '2': 'scan_sU',
    '3': 'sparta'
}

attack_input = input('Digite a opção: (0 - all, 1 - scan_A, 2 - scan_sU, 3 - sparta): ')
attack_name = attacks.get(attack_input)

# Caminhos do arquivo CSV
data_file_path = os.path.join('data_predictions - ' + attack_name + '.csv')

# Abre o arquivo CSV e extrai a coluna 'is_attack'
data_df = pd.read_csv(data_file_path)
y = data_df['is_attack']

output_dir = os.path.join('output_' + attack_name)
os.makedirs(output_dir, exist_ok=True)

for model_name in model_names:

    ################################################### REPORT AND LATENCY #################################################
    # Gera relatório para exibir
    y_pred = data_df[model_name]
    labels = [0, 1]
    target_names = label_to_index.keys()
    clf_report = classification_report(y, y_pred, labels=labels, target_names=target_names, digits=6, zero_division=0)

    # Exibe relatório
    print("-" * 26, 'binary', "-" * 26, '\n')
    print(clf_report)
    print("-" * 60)


    # Salva métricas em arquivo
    with open(os.path.join(output_dir, "binary_model_results.txt"), "a") as f:
        f.write(f"Modelo: {model_name}\n")
        f.write(clf_report + "\n")
        f.write("-" * 60 + '\n\n')

    # Extrai métricas para gráfico
    clf_report_dict = classification_report(y, y_pred, labels=labels, target_names=target_names, digits=6,
                                            zero_division=0, output_dict=True)
    precision = clf_report_dict["macro avg"]["precision"]
    recall = clf_report_dict["macro avg"]["recall"]
    f1_score = clf_report_dict["macro avg"]["f1-score"]
    accuracy = clf_report_dict["accuracy"]
    avg_metrics = {'Precison': precision, 'Recall': recall, 'F1_score': f1_score, 'Accuracy': accuracy}

    lines = []
    for metric, value in avg_metrics.items():
        lines.append({'Model': model_name, 'Metric': metric, 'Value': value})

    # DataFrame de métricas por modelo
    models_metrics_df = pd.concat([models_metrics_df, pd.DataFrame(lines)], axis=0, ignore_index=True)

    ################################################## MATRIZ DE CONFUSÃO ##################################################
    # Rótulos
    labels = [0, 1]
    labels_cat = ["Benign", "Malign"]

    # Calcular a matriz
    cm = confusion_matrix(y, y_pred, labels=labels)
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
    plt.title(f"Confusion matrix - {model_name} - binary", fontsize=16)
    plt.xlabel("Predicted class", fontsize=16)
    plt.ylabel("True class", fontsize=16)

    # Ajustar ticks
    plt.xticks(fontsize=14, rotation=45, ha='right')
    plt.yticks(fontsize=14, rotation=0)

    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, f"confusion_matrix_binary_{model_name}.pdf"), dpi=300)
    plt.savefig(os.path.join(output_dir, f"confusion_matrix_binary_{model_name}.png"), dpi=300)
    print("-> Matriz de confusão salva na pasta: " + output_dir + '\n\n')

    ###################################################### CHARTS ##########################################################
    # Ajusta tamanho da fonte dos gráficos
plt.rcParams.update({'font.size': 16})

# Tamanho da fonte global e Estilo visual do seaborn
sns.set_context("notebook", font_scale=1.2)
sns.set_style("whitegrid")

# Gráfico de barras agrupadas - MÉTRICAS
data = models_metrics_df[models_metrics_df['Metric'] != 'Latency']
plt.figure(figsize=(12, 6))
ax = sns.barplot(data=data, x="Metric", y="Value", hue="Model", palette="Set2")

# Customizações
ax.set_title("Comparison of Models by Metric (binary)")
max_val = data['Value'].max()
ax.set_ylim(0, max_val * 1.1)  # margem de 10%
ax.legend(title="Models", bbox_to_anchor=(1.05, 1), loc="upper left")

for container in ax.containers:
    labels = [f'{(bar.get_height() * 100):.1f}%' for bar in container]
    ax.bar_label(container, labels=labels, label_type='edge', padding=3)

plt.tight_layout()
plt.savefig(os.path.join(output_dir, "metrics_bar_graph.pdf"), dpi=300)
plt.savefig(os.path.join(output_dir, "metrics_bar_graph.png"), dpi=300)
print("-> Gráfico de comparação dos modelos por métrica salvo na pasta " + output_dir)
plt.close()
