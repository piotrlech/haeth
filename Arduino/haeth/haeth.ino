/*
  Web Server

 A simple web server that shows the value of the analog input pins.
 using an Arduino Wiznet Ethernet shield.

 Circuit:
 * Ethernet shield attached to pins 10, 11, 12, 13
 * Analog inputs attached to pins A0 through A5 (optional)

 created 18 Dec 2009
 by David A. Mellis
 modified 9 Apr 2012
 by Tom Igoe

 */

#include <SPI.h>
#include <Ethernet.h>
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

// Enter a MAC address and IP address for your controller below.
// The IP address will be dependent on your local network:
byte mac[] = {
  0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED
};
IPAddress ip(192, 168, 100, 149);

// Initialize the Ethernet server library
// with the IP address and port you want to use
// (port 80 is default for HTTP):
EthernetServer server(80);

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

uint8_t buffer[BUFFER_SIZE+1];
int bufindex = 0;
char action[MAX_ACTION+1];
char path[MAX_PATH+1];
char command[MAX_ACTION+1];
char nonce[MAX_PATH+1];
char hmac[MAX_PATH+1];
int resetLevel = 0;


void setup() {
  // Open serial communications and wait for port to open:
  Serial.begin(9600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for Leonardo only
  }
  // Transmitter is connected to Arduino Pin #8
  mySwitch.enableTransmit(8);
  Alarm.timerRepeat(60, onWDT);
  //Serial.print("Free RAM: "); Serial.println(getFreeRam(), DEC);

  // start the Ethernet connection and the server:
  Ethernet.begin(mac, ip);
  server.begin();
  Serial.print("Server is at ");
  Serial.println(Ethernet.localIP());
}


void loop() {
  // listen for incoming clients
  EthernetClient client = server.available();
  if (client) {
    Serial.println("new client");
    // an http request ends with a blank line
    boolean currentLineIsBlank = true;
    while (client.connected()) {
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

    if (parsed) {
      resetLevel = -1;
      Serial.println(F("Processing request"));
      Serial.print(F("Action: ")); Serial.println(action);
      Serial.print(F("Path: ")); Serial.println(path);
      if (strcmp(action, "GET") == 0) {
        // Respond with the path that was accessed.
        // First send the success response code.
        client.println(F("HTTP/1.1 200 OK"));
        Alarm.delay(1);
        // Then send a few headers to identify the type of data returned and that
        // the connection will not be held open.
        client.println(F("Content-Type: text/plain"));
        client.println(F("Connection: close"));
        client.println(F("Server: P5000"));
        // Send an empty line to signal start of body.
        client.println(F(""));
        // Now send the response data.
        client.println(F("Hello world!"));
        Alarm.delay(1);
        parsed = parsePath(path, command, nonce, hmac);
        if(parsed) {
          String beforeHmac = String();
          beforeHmac = beforeHmac + "/" + HMAC_PASS + "/" + command + "/" + nonce + "/";
          //Serial.println(beforeHmac);
          uint8_t *hash;
          Sha256.initHmac((uint8_t*)HMAC_KEY, 13); // key, and length of key in bytes
          Sha256.print(beforeHmac);
          hash = Sha256.resultHmac();
          String strNonce = String();
          strNonce = nonce;
          unsigned long lngNonce = strNonce.toInt();
          //Serial.print("nonces "); Serial.print(eepromGetLng()); Serial.print(" vs "); Serial.println(lngNonce);

          if ((strcmp(hmac, bin2hex(hash)) == 0) && (eepromGetLng() < lngNonce))
          //if(true)
          {
            eepromPutLng(lngNonce);
            //Serial.print("eepromGetLng "); Serial.println(eepromGetLng());
          
            client.println(F("Cool!"));
            Serial.println(F("Cool!"));
            if (strcmp(command, "l1n") == 0)
              set_digitalwrite(11, HIGH);
            else if (strcmp(command, "l1f") == 0)
              set_digitalwrite(11, LOW);
            else if (strcmp(command, "l2n") == 0)
              set_digitalwrite(10, HIGH);
            else if (strcmp(command, "l2f") == 0)
              set_digitalwrite(10, LOW);
          }
          else
          {
            if (strcmp(hmac, bin2hex(hash)) != 0)
              client.println(F("Bad hash"));
            if (eepromGetLng() < lngNonce)
              client.println(F("Bad nonce"));
          }
        }
      }
    }
          
     /* if (client.available()) {
        char c = client.read();
        Serial.write(c);
        // if you've gotten to the end of the line (received a newline
        // character) and the line is blank, the http request has ended,
        // so you can send a reply
        if (c == '\n' && currentLineIsBlank) {
          // send a standard http response header
          client.println("HTTP/1.1 200 OK");
          client.println("Content-Type: text/html");
          client.println("Connection: close");  // the connection will be closed after completion of the response
          //client.println("Refresh: 5");  // refresh the page automatically every 5 sec
          client.println();
          client.println("<!DOCTYPE HTML>");
          client.println("<html>");
          // output the value of each analog input pin
          for (int analogChannel = 0; analogChannel < 6; analogChannel++) {
            int sensorReading = analogRead(analogChannel);
            client.print("analog input ");
            client.print(analogChannel);
            client.print(" is ");
            client.print(sensorReading);
            client.println("<br />");
          }
          client.println("</html>");
          break;
        }
        if (c == '\n') {
          // you're starting a new line
          currentLineIsBlank = true;
        }
        else if (c != '\r') {
          // you've gotten a character on the current line
          currentLineIsBlank = false;
        }
      }
    }*/
    // give the web browser time to receive the data
    delay(1);
    // close the connection:
    client.stop();
    Serial.println("client disconnected");
  }
  }
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

bool parseRequest(uint8_t* buf, int bufSize, char* action, char* path) 
{
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
  /*uint32_t ipAddress, netmask, gateway, dhcpserv, dnsserv;
  
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
  }*/
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
  /*if (resetLevel < 0)
    resetLevel = 0;
  else {
    uint32_t ip = cc3000.IP2U32(192, 168, 1, 1);;
    Serial.print(F("WDT: pinging ... "));
    uint8_t replies = cc3000.ping(ip, 5);
    Serial.print(replies); Serial.println(F(" replies"));
    if (replies < 5) {
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
  }*/
}


