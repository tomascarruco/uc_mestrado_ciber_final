#include <Arduino.h>

void
setup ()
{
    Serial.begin (9600);
    while (!Serial.available ())
        ;
}

void
loop ()
{
    Serial.println ("Hello");
    delay (1 * 1000);
    Serial.println ("Hello");
    delay (1 * 1000);
}
