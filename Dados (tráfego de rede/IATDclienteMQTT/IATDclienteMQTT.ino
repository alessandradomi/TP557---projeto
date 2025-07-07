#include <WiFi.h>
#include <PubSubClient.h>

// Configurações da rede Wi-Fi
const char* ssid = "SSID";
const char* password = "PASSWORD";

// IP fixo
IPAddress local_IP(192, 168, 100, 3);
IPAddress gateway(192, 168, 100, 1);
IPAddress subnet(255, 255, 255, 0);
IPAddress primaryDNS(8, 8, 8, 8); // Opcional

// Configurações do broker MQTT
const char* mqtt_server = "192.168.100.2";
const int mqtt_port = 1883;
const char* mqtt_user = "esp32-IATD";
const char* mqtt_password = "IATD@mtel";

// Tópicos MQTT
const char* publish_topic = "rasp-IATD";
const char* subscribe_topic = "ESP32-IATD";

// Objetos WiFi e MQTT
WiFiClient espClient;
PubSubClient client(espClient);

// Controle de tempo para envio periódico
unsigned long lastMsg = 0;
const long interval = 500;

void setup_wifi() {
  delay(10);
  Serial.println();
  Serial.print("Conectando-se a ");
  Serial.println(ssid);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }

  Serial.println("");
  Serial.println("WiFi conectado");
  Serial.println("Endereço IP: ");
  Serial.println(WiFi.localIP());
}

// Função chamada ao receber mensagem no tópico inscrito
void callback(char* topic, byte* payload, unsigned int length) {
  Serial.print("Mensagem recebida [");
  Serial.print(topic);
  Serial.print("]: ");
  for (unsigned int i = 0; i < length; i++) {
    Serial.print((char)payload[i]);
  }
  Serial.println();
}

// Reconecta ao MQTT se necessário
void reconnect() {
  while (!client.connected()) {
    Serial.print("Tentando conexão MQTT...");
    String clientId = "ESP32Client-";
    clientId += String(random(0xffff), HEX);

    if (client.connect(clientId.c_str(), mqtt_user, mqtt_password)) {
      Serial.println("Conectado ao broker MQTT");
      client.subscribe(subscribe_topic);
    } else {
      Serial.print("Falha na conexão. Código: ");
      Serial.print(client.state());
      Serial.println(" Tentando novamente em 5 segundos...");
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(115200);
  setup_wifi();
  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(callback);
}

void loop() {
  if (!client.connected()) {
    reconnect();
  }
  client.loop();

  unsigned long now = millis();
  if (now - lastMsg > interval) {
    lastMsg = now;
    int randNumber = random(0, 1000);
    String msg = "Hello raspi! #" + String(randNumber);
    Serial.print("Publicando mensagem: ");
    Serial.println(msg);
    client.publish(publish_topic, msg.c_str());
  }
}
