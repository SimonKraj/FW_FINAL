#include <M5StickC.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include "JWT.h"


//#define SEC_TO_EXPIRE 6000

const char* ssid       = "ADB-CFF9A1";
const char* password   = "rce6bn743cjr";
const char* ntpServer = "pool.ntp.org";
const long  gmtOffset_sec = 3600;
const int   daylightOffset_sec = 3600;
const int   sec_to_expire = 6000;

char* server_name = "https://fei.edu.r-das.sk:51415/api/v1/Auth";
const char* token = "Bearer eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjczYzMyNmY5NjY5ZTM2OTY2MmZlM2NlMWZhYmY5ZGYzMmNjODdlY2EwNzgwNzk1YzQ3NzNmZWRkNGY1N2Y5YjUifQ.eyJzdWIiOiJhOTMzYWY1ZGQzYjE2YjIyIiwiaWF0IjoiMTYxNDYyMzgxMiIsImV4cCI6IjE2MTQ2Mjk4MTIifQ.xX_yNcJVz3ItrskTxu5ro2nIBUBAO_XmVNe45O5W3_-v0C3GUdvgBtVpXagFJYAffNwzXkoXn777FaGADTGA7K";
 char* payload = "[{\"LoggerName\": \"Pot\",\"Timestamp\": 1614265180,\"MeasuredData\": [{\"Name\": \"napatie\",\"Value\": 50}],\"ServiceData\": [],\"DebugData\": [],\"DeviceId\": \"08d8d99d-d947-4aaa-88bf-741908951af7\"}]"; 

const char* serial_num = "a933af5dd3b16b22";  //hard defined KID
//char *key_hex = "73c326f9669e369662fe3ce1fabf9df32cc87eca0780795c4773fedd4f57f9b5";/////////////////////////////////////////////////////////////////////////////////Test - JWT prejde na server, ale mne generuje jwt inak ako Viktorovi 
  
const char PUBLIC_KEY[] = "-----BEGIN PUBLIC KEY-----\n"
                          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvRbRZdlYoNjxfNBlmz2pvKLNBx33\n"
                          "8acIc8HVVel/+tgajPoiIKdExLkEGXaN+kigf6EKgm1C/qFx6GmtDucBXg==\n"
                          "-----END PUBLIC KEY-----";

const char PRIVATE_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                           "MHcCAQEEIAMLyN6ZrlN6t1M/zExoBDa45IHLcq1wf1iEvJXJs4RFoAoGCCqGSM49\n"
                           "AwEHoUQDQgAEvRbRZdlYoNjxfNBlmz2pvKLNBx338acIc8HVVel/+tgajPoiIKdE\n"
                           "xLkEGXaN+kigf6EKgm1C/qFx6GmtDucBXg==\n"
                           "-----END EC PRIVATE KEY-----";



void setup(){
  
 /* 
  char sha_pub_key[65]={0};
  char sha_pub_key_hex[65]={0};
  
  char hash_string[65]={0}; 
  char hash_string_test[65]={0};
  //char output_buffer_hex[32] ={0};
  */
  time_t time_iat,time_exp;
  struct tm timeinfo;

  
    M5.begin();
    M5.Axp.ScreenBreath(0);
    Serial.begin(115200);
    Serial.println("Boot");

    //wifi connect
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);
    while(WiFi.status() != WL_CONNECTED){
        delay(100);
        Serial.print(".");
    }
    Serial.println("Wifi OK!");

    configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
    LocalTime();

while(1){

    Send_to_server(PRIVATE_KEY, PUBLIC_KEY,sec_to_expire,serial_num,server_name, payload); 
  delay(1000);
    ////////////////////////////////////////GENERATE JWT TOKEN/////////////////////////////////////////
   /* //Encrypt_SHA256(PUBLIC_KEY,&sha_pub_key[0],&sha_pub_key_hex[0]);               //generate kid (public key hash sha256 in hex)    // not in use yet
    char *header = (char*) malloc(1+strlen("{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":}")+strlen(key_hex));
    sprintf(header,"{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"%s\"}",key_hex);
    char *vysledok_header = JWT_base_64_url(header);                              //Header in BASE64_URL  //free
  
   time(&time_iat);
   time_exp = time_iat + SEC_TO_EXPIRE;
   char *claim = (char*) malloc(25+strlen((const char*)("{\"sub\":\"%s\",\"iat\":%d,\"exp\":%d}"))+strlen(serial_num)+strlen((const char*)time_iat)+strlen((const char*)time_exp));  //free
   sprintf(claim,"{\"sub\":\"%s\",\"iat\":%lu,\"exp\":%lu}",serial_num,time_iat,time_exp);
   char *vysledok_claim = JWT_base_64_url(claim); 
   char *base64_header_claim = (char*) malloc(1+strlen((const char*)".")+strlen(vysledok_claim)+strlen(vysledok_header));     ///////////header+claim -> JWT Content    //free
   sprintf(base64_header_claim,"%s.%s",vysledok_header,vysledok_claim);
   Encrypt_SHA256(base64_header_claim,&hash_string[0],&hash_string_test[0]); 
   char output_buffer_hex[65] ={0};
   ECDSA_signature_det(PRIVATE_KEY,hash_string,&output_buffer_hex[0]);
   char *base64_sign = JWT_base_64_url(output_buffer_hex);      
   //Serial.print("\nBase64_sign ->");
   //Serial.print(output_buffer_hex);              
   char *JWT_token = (char*)malloc(1+'.'+strlen(base64_header_claim)+strlen(base64_sign));  //free
   int sprintf_ret = sprintf(JWT_token, "%s.%s",base64_header_claim, base64_sign);
  */
/////////////////////////////////////////////////////////////END OF GENERATE JWT TOKEN/////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////SEND TO SERVER/////////////////////////////////////////////////////////////////////////   

/*    HTTPClient http;
    http.begin(serverName);
    char *bearer_token = (char*)malloc(1+strlen(JWT_token)+strlen("Bearer ")); //free
    sprintf(bearer_token,"%s%s","Bearer ", JWT_token);
    Serial.print("\nBearer token -> ");
    Serial.print(bearer_token);
   // Serial.print("\nDef token -> ");
   // Serial.print(token);
    http.addHeader("Content-Type","application/json");
    http.addHeader("Authorization",bearer_token);       
    int ret = http.POST(payload);
    Serial.print("\n HTTP Code ");                                          // sendim na server
    Serial.print(ret);
    String server_response = http.getString();
    Serial.print("\nServer response ");
    Serial.print(server_response);
    Serial.print("\n\n\n\n\n");
    http.end();

   // free(header);
    free(bearer_token);
    free(JWT_token);
    free(base64_header_claim);
    free(claim);
     */
   // delay(1000);
    
    }
}

void loop(){

}
