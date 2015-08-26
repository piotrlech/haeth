
/***************************************************
  Adafruit CC3000 Breakout/Shield Simple HTTP Server
    
  This is a simple implementation of a bare bones
  HTTP server that can respond to very simple requests.
  Note that this server is not meant to handle high
  load, concurrent connections, SSL, etc.  A 16mhz Arduino 
  with 2K of memory can only handle so much complexity!  
  This server example is best for very simple status messages
  or REST APIs.

  See the CC3000 tutorial on Adafruit's learning system
  for more information on setting up and using the
  CC3000:
    http://learn.adafruit.com/adafruit-cc3000-wifi  
    
  Requirements:
  
  This sketch requires the Adafruit CC3000 library.  You can 
  download the library from:
    https://github.com/adafruit/Adafruit_CC3000_Library
  
  For information on installing libraries in the Arduino IDE
  see this page:
    http://arduino.cc/en/Guide/Libraries
  
  Usage:
    
  Update the SSID and, if necessary, the CC3000 hardware pin 
  information below, then run the sketch and check the 
  output of the serial port.  After connecting to the 
  wireless network successfully the sketch will output 
  the IP address of the server and start listening for 
  connections.  Once listening for connections, connect
  to the server IP from a web browser.  For example if your
  server is listening on IP 192.168.1.130 you would access
  http://192.168.1.130/ from your web browser.
  
  Created by Tony DiCola and adapted from HTTP server code created by Eric Friedrich.
  
  This code was adapted from Adafruit CC3000 library example 
  code which has the following license:
  
  Designed specifically to work with the Adafruit WiFi products:
  ----> https://www.adafruit.com/products/1469

  Adafruit invests time and resources providing this open source code, 
  please support Adafruit and open-source hardware by purchasing 
  products from Adafruit!

  Written by Limor Fried & Kevin Townsend for Adafruit Industries.  
  BSD license, all text above must be included in any redistribution      
 ****************************************************/
#include <Adafruit_CC3000.h>
#include <SPI.h>
#include "utility/debug.h"
#include "utility/socket.h"
#include <RCSwitch.h>
#include <Wire.h>
#include <Time.h>
#include <TimeAlarms.h>
#include <DS1307RTC.h>
#include <EEPROM.h>
#include <avr/pgmspace.h>
#include <avr/wdt.h>
#include "sha256.h"
#include "piotr.h"
#include "pass.h"

static PROGMEM prog_uint32_t crc_table[16] = {
    0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
    0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
    0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
    0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c
};

#define START_CMD_CHAR '*'
#define END_CMD_CHAR '#'
#define DIV_CMD_CHAR '|'

#define CMD_TURN_IT_ON_OFF 10
#define CMD_READ_STATUS 11
#define CMD_SEND_TRIGGERS 12
#define CMD_SET_TIME 13

#define MAX_COMMAND 20  // max command number code. used for error checking.
#define MIN_COMMAND 10  // minimum command number code. used for error checking. 
#define IN_STRING_LENGHT 40
#define MAX_ANALOGWRITE 255
#define PIN_HIGH 3
#define PIN_LOW 2
#define MY_1ST    "10000"
#define MY_2ND    "01000"
#define MY_3RD    "00100"
#define MY_4TH    "00010"
#define MY_5TH    "10000"
#define MY_6TH    "00010"

String inText;
RCSwitch mySwitch = RCSwitch();
// the current address in the EEPROM (i.e. which byte we're going to write to next)
int eeprom_addr = 0;
AlarmId onTimer = 255;
AlarmId offTimer = 255;
tmElements_t tm;
unsigned long prevNonce = 179124;
unsigned long currNonce = 0;
int nonceAddr = 240;

// These are the interrupt and control pins
#define ADAFRUIT_CC3000_IRQ   3  // MUST be an interrupt pin!
// These can be any two pins
#define ADAFRUIT_CC3000_VBAT  5
#define ADAFRUIT_CC3000_CS    10
// Use hardware SPI for the remaining pins
// On an UNO, SCK = 13, MISO = 12, and MOSI = 11

Adafruit_CC3000 cc3000 = Adafruit_CC3000(ADAFRUIT_CC3000_CS, ADAFRUIT_CC3000_IRQ, ADAFRUIT_CC3000_VBAT,
                                         SPI_CLOCK_DIVIDER); // you can change this clock speed

// Security can be WLAN_SEC_UNSEC, WLAN_SEC_WEP, WLAN_SEC_WPA or WLAN_SEC_WPA2
#define WLAN_SECURITY   WLAN_SEC_WPA2

#define LISTEN_PORT           80      // What TCP port to listen on for connections.  
                                      // The HTTP protocol uses port 80 by default.

#define MAX_ACTION            10      // Maximum length of the HTTP action that can be parsed.

#define MAX_PATH              100      // Maximum length of the HTTP request path that can be parsed.
                                      // There isn't much memory available so keep this short!

#define BUFFER_SIZE           MAX_ACTION + MAX_PATH + 20  // Size of buffer for incoming request data.
                                                          // Since only the first line is parsed this
                                                          // needs to be as large as the maximum action
                                                          // and path plus a little for whitespace and
                                                          // HTTP version.

#define TIMEOUT_MS            500    // Amount of time in milliseconds to wait for
                                     // an incoming request to finish.  Don't set this
                                     // too high or your server could be slow to respond.

Adafruit_CC3000_Server httpServer(LISTEN_PORT);
uint8_t buffer[BUFFER_SIZE+1];
int bufindex = 0;
char action[MAX_ACTION+1];
char path[MAX_PATH+1];
char command[MAX_ACTION+1];
char nonce[MAX_PATH+1];
char hmac[MAX_PATH+1];
int resetLevel = 0;

void setup(void) {
  // Transmitter is connected to Arduino Pin #8
  mySwitch.enableTransmit(8);
  Alarm.timerRepeat(60, onWDT);
  
  Serial.begin(115200);
  Serial.println(F("Hello, CC3000!\n")); 
  //eepromPutLng(prevNonce);
  //Serial.print("eepromGetLng "); Serial.println(eepromGetLng());

  Serial.print("Free RAM: "); Serial.println(getFreeRam(), DEC);
  serverStart();
  //void(* resetFunc) (void) = 0; //declare reset function at address 0
}

void loop(void)
{
  Alarm.delay(0);
  // Try to get a client which is connected.
  Adafruit_CC3000_ClientRef client = httpServer.available();
  if (client) {
    Serial.println(F("Client connected."));
    // Process this request until it completes or times out.
    // Note that this is explicitly limited to handling one request at a time!

    // Clear the incoming data buffer and point to the beginning of it.
    bufindex = 0;
    memset(&buffer, 0, sizeof(buffer));
    
    // Clear action and path strings.
    memset(&action,  0, sizeof(action));
    memset(&path,    0, sizeof(path));
    memset(&command, 0, sizeof(command));
    memset(&nonce,   0, sizeof(nonce));
    memset(&hmac,    0, sizeof(hmac));

    // Set a timeout for reading all the incoming data.
    unsigned long endtime = millis() + TIMEOUT_MS;
    
    // Read all the incoming data until it can be parsed or the timeout expires.
    bool parsed = false;
    while (!parsed && (millis() < endtime) && (bufindex < BUFFER_SIZE)) {
      if (client.available()) {
        buffer[bufindex++] = client.read();
      }
      parsed = parseRequest(buffer, bufindex, action, path);
      Alarm.delay(0);
    }

    // Handle the request if it was parsed.
    if (parsed) {
      resetLevel = -1;
      Serial.println(F("Processing request"));
      Serial.print(F("Action: ")); Serial.println(action);
      Serial.print(F("Path: ")); Serial.println(path);
      if (strcmp(action, "GET") == 0) {
        // Respond with the path that was accessed.
        // First send the success response code.
        client.fastrprintln(F("HTTP/1.1 200 OK"));
        Alarm.delay(1);
        // Then send a few headers to identify the type of data returned and that
        // the connection will not be held open.
        client.fastrprintln(F("Content-Type: text/plain"));
        client.fastrprintln(F("Connection: close"));
        client.fastrprintln(F("Server: Adafruit CC3000"));
        //Alarm.delay(1);
        // Send an empty line to signal start of body.
        client.fastrprintln(F(""));
        // Now send the response data.
        client.fastrprintln(F("Hello world!"));
        Alarm.delay(1);
        if (strcmp(path, "/stop") == 0) {
          /* You need to make sure to clean up after yourself or the CC3000 can freak out */
          /* the next time you try to connect ... */
          Serial.println(F("\n\nDisconnecting now"));
          cc3000.disconnect();
        }
        else {
          parsed = parsePath(path, command, nonce, hmac);
          if(parsed) {
            String beforeHmac = "";
            beforeHmac = "/" + HMAC_PASS + "/ + command + "/" + nonce + "/";
            //Serial.println(beforeHmac);
            uint8_t *hash;
            Sha256.initHmac((uint8_t*)HMAC_KEY, 3); // key, and length of key in bytes
            Sha256.print(beforeHmac);
            hash = Sha256.resultHmac();
            //Serial.println(F("The hash result is then stored in hash[0], hash[1] .. hash[31]"));
            // HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = 
            // 0xf7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
            //String stringOne = String(hash[0], HEX) + String(10, HEX);
            //Serial.println(stringOne);
            //stringOne = String(256 * hash[1] + hash[0], HEX);
            //Serial.println(stringOne);
            //Serial.println(command);
            //Serial.print("Free RAM: "); Serial.println(getFreeRam(), DEC);
            //Serial.println(hmac);
            //Serial.println(bin2hex(hash));
            //Serial.println(strlen(hmac));
            //Serial.println(strlen(bin2hex(hash)));
            String strNonce = String();
            strNonce = nonce;
            unsigned long lngNonce = strNonce.toInt();
            //Serial.print("nonces "); Serial.print(eepromGetLng()); Serial.print(" vs "); Serial.println(lngNonce);

            if ((strcmp(hmac, bin2hex(hash)) == 0) && (eepromGetLng() < lngNonce))
            {
              eepromPutLng(lngNonce);
              //Serial.print("eepromGetLng "); Serial.println(eepromGetLng());
            
              client.fastrprintln(F("Cool!"));
              Serial.println(F("Cool!"));
              if (strcmp(command, "l1n") == 0)
                set_digitalwrite(11, HIGH);
              else if (strcmp(command, "l1f") == 0)
                set_digitalwrite(11, LOW);
              else if (strcmp(command, "l1n") == 0)
                set_digitalwrite(10, HIGH);
              else if (strcmp(command, "l1f") == 0)
                set_digitalwrite(10, LOW);
            }
          }
        }
        //client.fastrprint(F("You accessed path: ")); client.fastrprintln(path);
      }
      else if (strcmp(action, "POST") == 0) {
        // Respond with the path that was accessed.
        // First send the success response code.
        client.fastrprintln(F("HTTP/1.1 200 OK"));
        // Then send a few headers to identify the type of data returned and that
        // the connection will not be held open.
        client.fastrprintln(F("Content-Type: text/plain"));
        client.fastrprintln(F("Connection: close"));
        client.fastrprintln(F("Server: Adafruit CC3000"));
        // Send an empty line to signal start of body.
        client.fastrprintln(F(""));
        // Now send the response data.
        client.fastrprint(F("Hello! "));
        client.fastrprint(F("You accessed path: ")); client.fastrprintln(path);
        if (strcmp(path, "/stop") == 0) {
          /* You need to make sure to clean up after yourself or the CC3000 can freak out */
          /* the next time you try to connect ... */
          Serial.println(F("\n\nClosing the connection"));
          cc3000.disconnect();
        }
      }
      else {
        // Unsupported action, respond with an HTTP 405 method not allowed error.
        client.fastrprintln(F("HTTP/1.1 405 Method Not Allowed"));
        client.fastrprintln(F(""));
      }
    }

    // Wait a short period to make sure the response had time to send before
    // the connection is closed (the CC3000 sends data asyncronously).
    Alarm.delay(100);

    // Close the connection when done.
    Serial.println(F("Client disconnected"));
    client.close();
  }
  else
    Alarm.delay(1);
}

// Return true if the buffer contains an HTTP request.  Also returns the request
// path and action strings if the request was parsed.  This does not attempt to
// parse any HTTP headers because there really isn't enough memory to process
// them all.
// HTTP request looks like:
//  [method] [path] [version] \r\n
//  Header_key_1: Header_value_1 \r\n
//  ...
//  Header_key_n: Header_value_n \r\n
//  \r\n
bool parseRequest(uint8_t* buf, int bufSize, char* action, char* path) {
  // Check if the request ends with \r\n to signal end of first line.
  if (bufSize < 2)
    return false;
  if (buf[bufSize-2] == '\r' && buf[bufSize-1] == '\n') {
    parseFirstLine((char*)buf, action, path);
    return true;
  }
  return false;
}

// Parse the action and path from the first line of an HTTP request.
void parseFirstLine(char* line, char* action, char* path) {
  // Parse first word up to whitespace as action.
  char* lineaction = strtok(line, " ");
  if (lineaction != NULL)
    strncpy(action, lineaction, MAX_ACTION);
  // Parse second word up to whitespace as path.
  char* linepath = strtok(NULL, " ");
  if (linepath != NULL)
    strncpy(path, linepath, MAX_PATH);
}

bool parsePath(char* path, char* command, char* nonce, char* hmac) {
  // Parse first word up to whitespace as action.
  char* lineaction = strtok(path, "/");
  if (lineaction != NULL)
    strncpy(command, lineaction, MAX_ACTION);
  // Parse second word up to whitespace as path.
  char* linepath = strtok(NULL, "/");
  if (linepath != NULL)
    strncpy(nonce, linepath, MAX_PATH);
  char* linehmac = strtok(NULL, "/");
  if (linehmac != NULL)
    strncpy(hmac, linehmac, MAX_PATH);
  else
    return false;
  return true;
}

// Tries to read the IP address and other connection details
bool displayConnectionDetails(void)
{
  uint32_t ipAddress, netmask, gateway, dhcpserv, dnsserv;
  
  if(!cc3000.getIPAddress(&ipAddress, &netmask, &gateway, &dhcpserv, &dnsserv))
  {
    Serial.println(F("Unable to retrieve the IP Address!\r\n"));
    return false;
  }
  else
  {
    Serial.print(F("\nIP Addr: ")); cc3000.printIPdotsRev(ipAddress);
    Serial.print(F("\nNetmask: ")); cc3000.printIPdotsRev(netmask);
    Serial.print(F("\nGateway: ")); cc3000.printIPdotsRev(gateway);
    Serial.print(F("\nDHCPsrv: ")); cc3000.printIPdotsRev(dhcpserv);
    Serial.print(F("\nDNSserv: ")); cc3000.printIPdotsRev(dnsserv);
    Serial.println();
    return true;
  }
}

void setUpStatus()
{
  for(int i = 0; i < 6; i++) {
    if(EEPROM.read(101+i) == HIGH) {
      switch (i+1) {
      case 1:
        mySwitch.switchOn(MY_GROUP2, MY_1ST);
        break;
      case 2:
        mySwitch.switchOn(MY_GROUP2, MY_2ND);
        break;
      case 3:
        mySwitch.switchOn(MY_GROUP2, MY_3RD);
        break;
      case 4:
        mySwitch.switchOn(MY_GROUP2, MY_4TH);
        break;
      case 5:
        mySwitch.switchOn(MY_GROUP2, MY_5TH);
        break;
      case 6:
        mySwitch.switchOn(MY_GROUP2, MY_6TH);
        break;
      }
    } else {
      switch (i+1) {
      case 1:
        mySwitch.switchOff(MY_GROUP2, MY_1ST);
        break;
      case 2:
        mySwitch.switchOff(MY_GROUP2, MY_2ND);
        break;
      case 3:
        mySwitch.switchOff(MY_GROUP2, MY_3RD);
        break;
      case 4:
        mySwitch.switchOff(MY_GROUP2, MY_4TH);
        break;
      case 5:
        mySwitch.switchOff(MY_GROUP2, MY_5TH);
        break;
      case 6:
        mySwitch.switchOff(MY_GROUP2, MY_6TH);
        break;
      }
    }
  }
}

void setUpAlarms()
{
  for(int i = 0; i < 6; i++) {
    eeprom_addr = 4 * i;
    //Serial.print(i+1);
    //Serial.print(" --> ");
    int h = EEPROM.read(eeprom_addr++);
    int m = EEPROM.read(eeprom_addr++);
    //printTimeStamp(h, m);
    //Serial.print(",  ");
    if (h < 24 && m < 60) {
      switch (i+1) {
      case 1:
        Alarm.alarmRepeat(h, m, 0, onAlarm1);
        Alarm.alarmRepeat(h, m, 1, onAlarm1);
        break;
      case 2:
        Alarm.alarmRepeat(h, m, 0, onAlarm2);
        Alarm.alarmRepeat(h, m, 1, onAlarm2);
        break;
      case 3:
        Alarm.alarmRepeat(h, m, 0, onAlarm3);
        Alarm.alarmRepeat(h, m, 1, onAlarm3);
        break;
      case 4:
        Alarm.alarmRepeat(h, m, 0, onAlarm4);
        Alarm.alarmRepeat(h, m, 1, onAlarm4);
        break;
      case 5:
        Alarm.alarmRepeat(h, m, 0, onAlarm5);
        Alarm.alarmRepeat(h, m, 1, onAlarm5);
        break;
      case 6:
        Alarm.alarmRepeat(h, m, 0, onAlarm6);
        Alarm.alarmRepeat(h, m, 1, onAlarm6);
        break;
      }
    }
    h = EEPROM.read(eeprom_addr++);
    m = EEPROM.read(eeprom_addr++);
    //printTimeStamp(h, m);
    if (h < 24 && m < 60) {
      switch (i+1) {
      case 1:
        Alarm.alarmRepeat(h, m, 0, offAlarm1);
        Alarm.alarmRepeat(h, m, 1, offAlarm1);
        break;
      case 2:
        Alarm.alarmRepeat(h, m, 0, offAlarm2);
        Alarm.alarmRepeat(h, m, 1, offAlarm2);
        break;
      case 3:
        Alarm.alarmRepeat(h, m, 0, offAlarm3);
        Alarm.alarmRepeat(h, m, 1, offAlarm3);
        break;
      case 4:
        Alarm.alarmRepeat(h, m, 0, offAlarm4);
        Alarm.alarmRepeat(h, m, 1, offAlarm4);
        break;
      case 5:
        Alarm.alarmRepeat(h, m, 0, offAlarm5);
        Alarm.alarmRepeat(h, m, 1, offAlarm5);
        //Serial.print("(alarm off)");
        break;
      case 6:
        Alarm.alarmRepeat(h, m, 0, offAlarm6);
        int iRes = Alarm.alarmRepeat(h, m, 1, offAlarm6);
        //String sRes = "iRes = ";
        //sRes = sRes + iRes;
        //Serial.println(sRes);
        break;
      }
    }
   //Serial.println();
  }
  Serial.flush();
}

void onAlarm1(){
  mySwitch.switchOn(MY_GROUP2, MY_1ST);
  EEPROM.write(101, HIGH);
}

void offAlarm1(){
  mySwitch.switchOff(MY_GROUP2, MY_1ST);
  EEPROM.write(101, LOW);
}

void onAlarm2(){
  mySwitch.switchOn(MY_GROUP2, MY_2ND);
  EEPROM.write(102, HIGH);
}

void offAlarm2(){
  mySwitch.switchOff(MY_GROUP2, MY_2ND);
  EEPROM.write(102, LOW);
}

void onAlarm3(){
  mySwitch.switchOn(MY_GROUP2, MY_3RD);
  EEPROM.write(103, HIGH);
}

void offAlarm3(){
  mySwitch.switchOff(MY_GROUP2, MY_3RD);
  EEPROM.write(103, LOW);
}

void onAlarm4(){
  mySwitch.switchOn(MY_GROUP2, MY_4TH);
  EEPROM.write(104, HIGH);
}

void offAlarm4(){
  mySwitch.switchOff(MY_GROUP2, MY_4TH);
  EEPROM.write(104, LOW);
}

void onAlarm5(){
  digitalClockDisplay();
  Serial.println("Alarm#5: - turn it on");           
  Serial.flush();
  mySwitch.switchOn(MY_GROUP2, MY_5TH);
  EEPROM.write(105, HIGH);
}

void offAlarm5(){
  digitalClockDisplay();
  if(weekday() == 2 || weekday() == 3 || weekday() == 5 || weekday() == 6){
    Serial.println("Alarm#5: - turn it off");
    Serial.flush();
    mySwitch.switchOff(MY_GROUP2, MY_5TH);
    EEPROM.write(105, LOW);
  }
}

void onAlarm6(){
  digitalClockDisplay();
  if(weekday() == 2 || weekday() == 3 || weekday() == 5 || weekday() == 6){
    Serial.println("Alarm#6: - turn it on");           
    Serial.flush();
    mySwitch.switchOn(MY_GROUP2, MY_6TH);
    EEPROM.write(106, HIGH);
  }
}

void offAlarm6(){
  digitalClockDisplay();
  Serial.println("Alarm#6: - turn it off");           
  Serial.flush();
  mySwitch.switchOff(MY_GROUP2, MY_6TH);
  EEPROM.write(106, LOW);
}

// 2a) select the requested pin# for DigitalWrite action
void set_digitalwrite(int pin_num, int pin_value)
{
  tmElements_t tm;
    
  switch (pin_num) {
  case 13:
    //pinMode(13, OUTPUT);  // #1
    //digitalWrite(13, pin_value);
    EEPROM.write(101, pin_value);
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, MY_1ST);
    else
      mySwitch.switchOff(MY_GROUP2, MY_1ST);
    break;
  case 12:
    //pinMode(12, OUTPUT);  // #2
    //digitalWrite(12, pin_value);   
    EEPROM.write(102, pin_value);
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, MY_2ND);
    else
      mySwitch.switchOff(MY_GROUP2, MY_2ND);
    break;
  case 11:
    //pinMode(11, OUTPUT);  // #3
    //digitalWrite(11, pin_value);         
    EEPROM.write(103, pin_value);
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, MY_3RD);
    else
      mySwitch.switchOff(MY_GROUP2, MY_3RD);
    break;
  case 10:
    //pinMode(10, OUTPUT);  // #4
    //digitalWrite(10, pin_value);         
    EEPROM.write(104, pin_value);
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, MY_4TH);
    else
      mySwitch.switchOff(MY_GROUP2, MY_4TH);
    break;
  case 9:
    //pinMode(9, OUTPUT);  // #5
    //digitalWrite(9, pin_value);         
    EEPROM.write(105, pin_value);
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, MY_5TH);
    else
      mySwitch.switchOff(MY_GROUP2, MY_5TH);
    break;
  case 8:
    //pinMode(8, OUTPUT);  // #6
    //digitalWrite(8, pin_value);         
    EEPROM.write(106, pin_value);
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, MY_6TH);
    else
      mySwitch.switchOff(MY_GROUP2, MY_6TH);
    break;
  case 7:
    //pinMode(7, OUTPUT);  // #7
    //digitalWrite(7, pin_value);         
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, "00101");
    else
      mySwitch.switchOff(MY_GROUP2, "00101");
    break;
  case 6:
    //pinMode(6, OUTPUT);  // #8
    //digitalWrite(6, pin_value);         
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, "00110");
    else
      mySwitch.switchOff(MY_GROUP2, "00110");
    break;
  case 5:
    //pinMode(5, OUTPUT);  // #9
    //digitalWrite(5, pin_value); 
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, "00111");
    else
      mySwitch.switchOff(MY_GROUP2, "00111");
    break;
  case 4:
    //pinMode(4, OUTPUT);  // #10
    //digitalWrite(4, pin_value);         
    if(pin_value == HIGH)
      mySwitch.switchOn(MY_GROUP2, "01001");
    else
      mySwitch.switchOff(MY_GROUP2, "01001");
    break;
  case 3:
    //pinMode(3, OUTPUT);  // #11
    //digitalWrite(3, pin_value);         
    if (RTC.read(tm)) {
      Serial.print("Ok, Time = ");
      print2digits(tm.Hour);
      Serial.write(':');
      print2digits(tm.Minute);
      Serial.write(':');
      print2digits(tm.Second);
      Serial.print(", Date (D/M/Y) = ");
      Serial.print(tm.Day);
      Serial.write('/');
      Serial.print(tm.Month);
      Serial.write('/');
      Serial.print(tmYearToCalendar(tm.Year));
      Serial.println();
    } 
    break;
  case 2:
    //pinMode(2, OUTPUT);  // #12
    //digitalWrite(2, pin_value); 
    // add your code here       
    break;      
    // default: 
    // if nothing else matches, do the default
    // default is optional
  } 
}

void print2digits(int number) {
  if (number >= 0 && number < 10) {
    Serial.write('0');
  }
  Serial.print(number);
}

void printTimeStamp(int h, int m)
{
  Serial.print(h);
  printDigits(m);
}

void digitalClockDisplay()
{
  // digital clock display of the time
  Serial.print(hour());
  printDigits(minute());
  printDigits(second());
  Serial.println();
}

void printDigits(int digits)
{
  Serial.print(":");
  if(digits < 10)
    Serial.print('0');
  Serial.print(digits);
}

/*unsigned long crc_update(unsigned long crc, byte data)
{
    byte tbl_idx;
    tbl_idx = crc ^ (data >> (0 * 4));
    crc = pgm_read_dword_near(crc_table + (tbl_idx & 0x0f)) ^ (crc >> 4);
    tbl_idx = crc ^ (data >> (1 * 4));
    crc = pgm_read_dword_near(crc_table + (tbl_idx & 0x0f)) ^ (crc >> 4);
    return crc;
}

unsigned long crc_string(char *s)
{
  unsigned long crc = ~0L;
  while (*s)
    crc = crc_update(crc, *s++);
  crc = ~crc;
  return crc;
}

void print_crc()
{
  Serial.println(crc_string("HELLO"), HEX);
}*/

void temp()
{
  // Initialise the module
  Serial.println(F("\nInitializing..."));
  if (!cc3000.begin())
  {
    Serial.println(F("Couldn't begin()! Check your wiring?"));
    while(1);
  }
  
  Serial.print(F("\nAttempting to connect to ")); Serial.println(WLAN_SSID);
  if (cc3000.connectToAP(WLAN_SSID, WLAN_PASS, WLAN_SECURITY))
    Serial.println(F("Connected!"));
  else
    Serial.println(F("Failed!"));

    //while(1);
  /* Optional: Set a static IP address instead of using DHCP.
     Note that the setStaticIPAddress function will save its state
     in the CC3000's internal non-volatile memory and the details
     will be used the next time the CC3000 connects to a network.
     This means you only need to call the function once and the
     CC3000 will remember the connection details.  To switch back
     to using DHCP, call the setDHCP() function (again only needs
     to be called once).
  */
  
  /*uint32_t ipAddress = cc3000.IP2U32(192, 168, 100, 149);
  uint32_t netMask = cc3000.IP2U32(255, 255, 255, 128);
  uint32_t defaultGateway = cc3000.IP2U32(192, 168, 100, 253);
  uint32_t dns = cc3000.IP2U32(192, 168, 100, 253);
  if (!cc3000.setStaticIPAddress(ipAddress, netMask, defaultGateway, dns)) {
    Serial.println(F("Failed to set static IP!"));
    while(1);
  }*/
  
  /* Optional: Revert back from static IP addres to use DHCP.
     See note for setStaticIPAddress above, this only needs to be
     called once and will be remembered afterwards by the CC3000.
  */
  
  /*if (!cc3000.setDHCP()) {
    Serial.println(F("Failed to set DHCP!"));
    while(1);
  }
  

  
  Serial.println(F("Request DHCP"));
  while (!cc3000.checkDHCP())
  {
    delay(100); // ToDo: Insert a DHCP timeout!
  } 
  //CC3000::setStaticIPAddress(uint32_t ip, uint32_t subnetMask, uint32_t defaultGateway, uint32_t dnsServer)*/

  // Display the IP address DNS, Gateway, etc.
  while (! displayConnectionDetails()) {
    Alarm.delay(1000);
  }

  // ******************************************************
  // You can safely remove this to save some flash memory!
  // ******************************************************
  Serial.println(F("\r\nNOTE: This sketch may cause problems with other sketches"));
  Serial.println(F("since the .disconnect() function is never called, so the"));
  Serial.println(F("AP may refuse connection requests from the CC3000 until a"));
  Serial.println(F("timeout period passes.  This is normal behaviour since"));
  Serial.println(F("there isn't an obvious moment to disconnect with a server.\r\n"));
  
  // Start listening for connections
  httpServer.begin();
  Serial.println(F("Listening for connections..."));
}

void resetFunc()
{
  Serial.print("Reset now ");
  wdt_enable(WDTO_15MS);
  while(1){
    Serial.print(".");
  }
}
void eepromPutLng(unsigned long nonce) {
  uint8_t* bAddr = (uint8_t*) &nonce;
  
  //Serial.print("bAddr  "); Serial.println((int)bAddr);
  //Serial.print("&nonce "); Serial.println((int)(&nonce));
  
  EEPROM.write( nonceAddr+0, *(bAddr+0) );
  EEPROM.write( nonceAddr+1, *(bAddr+1) );
  EEPROM.write( nonceAddr+2, *(bAddr+2) );
  EEPROM.write( nonceAddr+3, *(bAddr+3) );
  //Serial.println(EEPROM.read(nonceAddr+0)); //0  179124
  //Serial.println(EEPROM.read(nonceAddr+1)); //1
  //Serial.println(EEPROM.read(nonceAddr+2)); //3
  //Serial.println(EEPROM.read(nonceAddr+3)); //255*/
}

long eepromGetLng() {
  long ret = EEPROM.read(nonceAddr);
  long mltp = 256;
  ret = ret + mltp * EEPROM.read(nonceAddr+1);
  mltp *= 256;
  ret = ret + mltp * EEPROM.read(nonceAddr+2);
  mltp *= 256;
  ret = ret + mltp * EEPROM.read(nonceAddr+3);
  return ret;
}

void onWDT(){
  if (resetLevel < 0)
    resetLevel = 0;
  else {
    uint32_t ip = cc3000.IP2U32(192, 168, 1, 1);;
    Serial.print(F("WDT: pinging ... "));
    uint8_t replies = cc3000.ping(ip, 3);
    Serial.print(replies); Serial.println(F(" replies"));
    if (replies < 2) {
      if (resetLevel > 10) {
        Serial.print(F("\n\nResetting Arduino. The reset level is ")); Serial.println(resetLevel);
        resetFunc(); //call reset
      }
      else {
        Serial.print(F("\n\nClosing the connection. The reset level is ")); Serial.println(resetLevel);
        cc3000.disconnect();
        cc3000.reboot();
        serverStart();
        resetLevel++;
      }
    }
    else
      resetLevel = 0;
  }
}

void serverStart()
{
  cc3000.begin();
  Serial.print(F("\nAttempting to connect to ")); Serial.println(WLAN_SSID);
  if (cc3000.connectToAP(WLAN_SSID, WLAN_PASS, WLAN_SECURITY)) {
    Serial.println(F("Connected!"));
    while (! displayConnectionDetails()) {
      Alarm.delay(1000);
    }
    httpServer.begin();
    Serial.println(F("Listening for connections..."));
  }
  else
    Serial.println(F("Failed!"));
}


