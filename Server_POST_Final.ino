#include <M5StickC.h>
//#include <WiFi.h>
#include <HTTPClient.h>
#include "mbedtls/md.h"
#include <AXP192.h> 
#include <Arduino.h>
#include <RTC.h>
#include "time.h"     
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "mbedtls/base64.h"
#include <base64.h>
#include <HTTPClient.h>

#define HTTP_SUCCESS 200


const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


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
unsigned char *key_hex =(uint8_t*)"73c326f9669e369662fe3ce1fabf9df32cc87eca0780795c4773fedd4f57f9b5";


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







void LocalTime();
uint8_t *JWT_base_64_url(uint8_t *base_str);
int ECDSA_signature_det(const char *private_key, uint8_t* input_buffer, uint8_t* output_buffer);


void setup(){
  
    time_t time_iat,time_exp;
    struct tm timeinfo;
    Serial.begin(115200);

  
    M5.begin();
    M5.Axp.ScreenBreath(0);
   
    Serial.println("Boot");
/*
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
*/
while(1)
  {

  //  HTTPClient http;
  //  http.begin(server_name);
    
    uint8_t hash_string[65]={0};
    char sha_pub_key[65]={0};
    char sha_pub_key_hex[65]={0};
    char hash_string_test[65]={0};
    uint8_t output_buffer_hex[65] ={0};


    uint8_t ecdsa_output_buffer[64];
    uint8_t hash[32];
    time_t time_iat;
    time_t time_exp;
    struct tm timeinfo;
    int sha_ret =0;
    size_t outlen;
    
    //uint8_t header = (uint8_t*)malloc(1 + (strlen("{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":}") + strlen((const char*)key_hex)));                  //generate header  
    char header[150]; 
    sprintf(header,"{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"%s\"}",(char*)key_hex);
    uint8_t *vysledok_header = JWT_base_64_url((uint8_t*)header);
    time(&time_iat);                                                                                                           //get fresh time for timestamp
    time_exp = time_iat + sec_to_expire;
    
    //uint8_t claim = (uint8_t*)malloc(25 + strlen((const char*)("{\"sub\":\"%s\",\"iat\":%d,\"exp\":%d}")) + strlen((const char*)serial_num) + strlen((const char*)time_iat) + strlen((const char*)time_exp));  //generate claim     
    char claim[200];
    sprintf(claim,"{\"sub\":\"%s\",\"iat\":%ld,\"exp\":%ld}",(char*)serial_num,(char*)time_iat,(char*)time_exp);

    uint8_t *vysledok_claim = JWT_base_64_url((uint8_t*)claim); 
    //uint8_t base64_header_claim = (uint8_t*)malloc(1 + strlen((const char*)".") + strlen((const char*)vysledok_claim) + strlen((const char*)vysledok_header));     ///////////header+claim -> JWT Content    
    char base64_header_claim[300];
    sprintf(base64_header_claim, "%s.%s", (char*)vysledok_header, (char*)vysledok_claim);
    
    Serial.print("\nSHA256 INPUT-> ");
    Serial.print((char*)base64_header_claim);
    int len_input = sizeof(base64_header_claim);                                                        
    int ret = mbedtls_sha256_ret((uint8_t*)base64_header_claim, len_input, hash, 0);                        ////HASH SHA256
 /* 
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256; 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  //mbedtls_md_update(&ctx,(unsigned char*)base64_header_claim, strlen((const char*) base64_header_claim));
  mbedtls_md_update(&ctx,(unsigned char*)base64_header_claim, sizeof(base64_header_claim));
  int ret = mbedtls_md_finish(&ctx,(unsigned char*)hash);
  mbedtls_md_free(&ctx);
*/
   Serial.print("\nHASH RET ->"); 
   Serial.print(ret);
   
   Serial.print("\nSHA256 LEN OUT-> ");
   //int a = strlen((const char*)hash);
   int a = sizeof(hash);
   Serial.print(a);
    
 //  Serial.print("\nHASH SHA256 RET->");     
 // Serial.print(ret);

      
 //  Serial.print("\nHASH SHA256 ->");      
 //  Serial.print((char*)hash);
 
   ECDSA_signature_det(PRIVATE_KEY, hash, ecdsa_output_buffer);
   uint8_t *sign = JWT_base_64_url(ecdsa_output_buffer);

   //uint8_t *JWT_token = (uint8_t*)malloc(1+strlen((const char*)base64_header_claim)+100);                                                     
   char JWT_token[250]; 
   //int sprintf_ret = sprintf(JWT_token, "%s.%s",base64_header_claim, base64_sign);
   sprintf((char*)JWT_token, "%s.%s", (char*)base64_header_claim, (char*)sign);

   //unsigned char *bearer_token = (uint8_t*)malloc(1+strlen((const char*)JWT_token)+strlen("Bearer ")); 
   char bearer_token[250];
   sprintf(bearer_token,"%s%s","Bearer ", (char*)JWT_token);
   //Serial.print("\nBearer token -> ");
   Serial.print("\n");
   Serial.println((char*)bearer_token);
   /*
   http.addHeader("Content-Type","application/json");
   http.addHeader("Authorization",(char*)bearer_token);                                                                             
   int ret = http.POST((char*)payload);
   Serial.print("\n HTTP Code ");                                          
   Serial.print(ret);
   String server_response = http.getString();
   Serial.print("\nServer response ");
   Serial.print(server_response);

    */
   // free(header);
   // free(claim);
   // free(base64_header_claim);
   // free(JWT_token);
    Serial.print("\n");
  delay(1000);
  }
}


void loop()
{

}



int ECDSA_signature_det(const char *private_key, uint8_t* input_buffer, uint8_t* output_buffer) 
  {
    mbedtls_ecdsa_context ecdsa_ctx; 
    mbedtls_pk_context pk_ctx;
    mbedtls_mpi r;
    mbedtls_mpi s;                       
                                                  ///////////////Initialization    
    mbedtls_pk_init(&pk_ctx);
    int pk_cont = mbedtls_pk_parse_key(&pk_ctx, (unsigned char*)private_key, strlen(private_key)+1, NULL, NULL);
    mbedtls_ecdsa_init(&ecdsa_ctx);
    int keypair = mbedtls_ecdsa_from_keypair(&ecdsa_ctx, mbedtls_pk_ec(pk_ctx));
    mbedtls_mpi_init(&s);
    mbedtls_mpi_init(&r);
    int verify = mbedtls_ecdsa_sign_det(&ecdsa_ctx.grp, &r, &s, &ecdsa_ctx.d, input_buffer, sizeof(input_buffer), MBEDTLS_MD_SHA256); 
    Serial.print("\nECDSA VERIFY-> ");
    Serial.print(verify);
    //int buffer_1 = mbedtls_mpi_write_binary(&r, output_buffer, mbedtls_mpi_size(&r)); 
    //int buffer_2 = mbedtls_mpi_write_binary(&s, output_buffer + mbedtls_mpi_size(&s), mbedtls_mpi_size(&s));
    int buffer_1 = mbedtls_mpi_write_binary(&r, output_buffer, 32); 
    int buffer_2 = mbedtls_mpi_write_binary(&s, output_buffer + 32, 32);

    Serial.print("\nECDSA CONT-> ");
    Serial.print(pk_cont);
    Serial.print("\nECDSA KEYPAIR-> ");
    Serial.print(keypair);
    Serial.print("\nECDSA VERIFY-> ");
    Serial.print(verify);
    Serial.print("\nECDSA BUF1-> ");
    Serial.print(buffer_1);
    Serial.print("\nECDSA BUF2-> ");
    Serial.print(buffer_2);
    Serial.print("\nECDSA LEN OUT-> ");
    int a = sizeof(output_buffer);
    Serial.print(a);
    Serial.print("\nECDSA OUT-> ");
    Serial.print((int)output_buffer,HEX);
  
    mbedtls_pk_free(&pk_ctx); 
    mbedtls_ecdsa_free(&ecdsa_ctx );
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s); 
   return 0; 
  }

void LocalTime()
{
  struct tm timeinfo;
  if(!getLocalTime(&timeinfo))
    {   
      Serial.println("Failed to obtain time");
      return;
    }
  Serial.println(&timeinfo, "%H:%M:%S");
  Serial.println("Timestamp: ");
  time_t timestamp;
  time(&timestamp);
}

uint8_t *JWT_base_64_url(uint8_t* base_str)   
{
  int olen =0;
  String out = base64::encode(base_str,strlen((const char*)base_str));
 // String out = base64::encode(base_str,sizeof(base_str));
 // uint8_t *result = (uint8_t*)malloc(sizeof(out)+1);
  uint8_t *result = (uint8_t*)malloc(strlen((const char*)out.c_str())+1);
 //uint8_t result[100];
  strcpy((char*)result,out.c_str()); 
  for(int x =0 ; x<(strlen((const char*)result));x++)
   {
      char c = *(result+x);
      switch(c)
      {
        case '+' : *(result+x) = '-';
                 break;
        case '/' :  *(result+x) = '_';
                break;
        case '=' :  *(result+x) = NULL;
                break; 
        default : break;
      }
   }  
    return result;
    free(result);
}
