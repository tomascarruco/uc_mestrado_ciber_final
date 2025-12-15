#include <Arduino.h>
#include <SPI.h>
#include <WiFiNINA.h>
#include <cstdint>

#include "PubSubClient.h"
#include "WiFi.h"
#include "WiFiClient.h"
#include "api/Common.h"
#include "api/IPAddress.h"
#include "secrets.h"
#include "variant.h"

#define PUB_TOPIC "main/one"
#define SERVER_ADDR "192.168.1.145"
#define SERVER_MQTT_PORT 1883

char ssid[] = AP_SSID;
char pass[] = AP_PASS;
int  status = WL_IDLE_STATUS;

IPAddress mqtt_server = IPAddress (SERVER_ADDR);

// Declarations
int  APConnect (const char ssid[], const char pass[]);
void reconnect ();
void callback (char *topic, byte *payload, unsigned int length);

WiFiClient   wifi_client;
PubSubClient client (wifi_client);

const char *device_name = "";

void
setup ()
{
    Serial.begin (9600);
    while (!Serial) {
        ; // wait for serial port to connect.
    }

    client.setServer (mqtt_server, SERVER_MQTT_PORT);
    client.setCallback (callback);

    int result = APConnect (ssid, pass);
    if (!result) {
        Serial.println ("[INFO] Connected to the AP!");
    } else {
        Serial.println ("[ERRR] Unable to Connect to the AP!");
    }
    delay (1.5 * 1000);

    IPAddress address = WiFi.localIP ();
    Serial.print ("[INFO] Current IP Addr: ");
    Serial.println (address.toString ());
}

void
loop ()
{
    if (!client.connected ())
        reconnect ();
    client.loop ();
}

// --- Functions - START

void
reconnect ()
{
    while (!client.connected ()) {
        Serial.println ("Attempting client connection");

        boolean client_connected = client.connect ("nano_33_iot");
        if (!client_connected) {
            Serial.println ("Failed connecting Client...");
            Serial.print ("Client state, rc=");
            Serial.println (client.state ());
            delay (3 * 1000);
            continue;
        }

        Serial.println ("Client connected!!!");
        client.subscribe (PUB_TOPIC);
        client.publish (PUB_TOPIC, "HELLO FROM NANO33IOT");
    }
}

int
APConnect (const char ssid[], const char pass[])
{
    String fv = WiFi.firmwareVersion ();
    if (fv < WIFI_FIRMWARE_LATEST_VERSION) {
        Serial.println ("[WARN] UPGRADE THE FIRMWARE!");
        return -1;
    }

    int retries    = 3;
    int iterations = 0;

    do {
        if (iterations >= retries)
            return -2;

        Serial.print ("[INFO] Attempting to connect to the WPA SSID: ");
        Serial.println (ssid);

        status = WiFi.begin (ssid, pass);

        delay (3 * 1000);
        iterations += 1;
    } while (status != WL_CONNECTED);

    return 0;
}

void
callback (char *topic, byte *payload, unsigned int length)
{
    Serial.print ("Payload: ");
    for (uint32_t i = 0; i < length; ++i) {
        Serial.print ((char) payload[i]);
    }
    Serial.print (" Topic: ");
    Serial.print (topic);
    Serial.print (" Length: ");
    Serial.print (length);

    Serial.println ();
}
