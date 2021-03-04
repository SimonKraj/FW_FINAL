#include "mbedtls/md.h"
#include <AXP192.h> 
#include <Arduino.h>
#include <RTC.h>
#include "time.h"     
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "JWT.h"
#include <base64.h>
#include <HTTPClient.h>

#define HTTP_SUCCESS 200

const char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



int Send_to_server(const char *private_key, const char *public_key, int sec_to_expire, const char *serial_num, char *end_point, char *payload_data) 
{
  HTTPClient http;
  http.begin(end_point);
  char *key_hex = "73c326f9669e369662fe3ce1fabf9df32cc87eca0780795c4773fedd4f57f9b5";/////////////////////////////////////////////////////////////////////////////////Test - JWT prejde na server, ale mne generuje jwt inak ako Viktorovi 
  int ret = 0;
  char hash_string[65]={0};
  char sha_pub_key[65]={0};
  char sha_pub_key_hex[65]={0};
 // int counter = 0;
   
  char hash_string_test[65]={0};
  uint8_t output_buffer_hex[65] ={0};
  //char output_buffer_hex[32] ={0};
  time_t time_iat,time_exp;
  struct tm timeinfo;
  int sha_ret =0;
    
   //Encrypt_SHA256(public_key,&sha_pub_key[0],&sha_pub_key_hex[0]);                                                          //generate kid (public key hash sha256 in hex)    // not in use yet
   //Serial.print("\nSHA256 PUB KEY -> ");
   //Serial.print(sha_pub_key_hex);
   char *header = (char*) malloc(1+strlen("{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":}")+strlen(key_hex));                  //generate header 
   sprintf(header,"{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"%s\"}",key_hex);
   char *vysledok_header = JWT_base_64_url(header);                                                                             
    
   time(&time_iat);                                                                                                           //get fresh time for timestamp
   time_exp = time_iat + sec_to_expire;
   char *claim = (char*) malloc(25+strlen((const char*)("{\"sub\":\"%s\",\"iat\":%d,\"exp\":%d}"))+strlen(serial_num)+strlen((const char*)time_iat)+strlen((const char*)time_exp));  //generate claim     
   sprintf(claim,"{\"sub\":\"%s\",\"iat\":%lu,\"exp\":%lu}",serial_num,time_iat,time_exp);
   char *vysledok_claim = JWT_base_64_url(claim); 
   char *base64_header_claim = (char*) malloc(1+strlen((const char*)".")+strlen(vysledok_claim)+strlen(vysledok_header));     ///////////header+claim -> JWT Content    
   sprintf(base64_header_claim,"%s.%s",vysledok_header,vysledok_claim);
   
   sha_ret = Encrypt_SHA256(base64_header_claim,&hash_string[0],&hash_string_test[0]);                                                  //Claim HASH SHA256
   Serial.print("\nHASH FOR ECDSA RET ->");
   Serial.print(sha_ret);
   Serial.print("\nHASH FOR ECDSA ->");
   Serial.print(hash_string_test);
   int leny = strlen(hash_string_test);
   Serial.print("\nHASH FOR ECDSA LEN ->");
   Serial.print(leny);

   ECDSA_signature_det(private_key,hash_string,&output_buffer_hex[0]);                                                        //Generate ECDSA signnature
   //char *base64_sign = JWT_base_64_url(output_buffer_hex);                 ////problem///////////////////////////////////////////////////////////////////////////////////////////////////////////
   String out = base64::encode(output_buffer_hex,64);
 //  Serial.print("\nOUT STRING ->           ");
 //  Serial.print(out);
  // char *result = (char*)malloc(out.length()+1);
  char *result = (char*)malloc(100);
  strcpy(result,out.c_str()); 
// memcpy(result,out,87);

 // for(x =0 ; x<(strlen(result));x++)
  for(int x =0 ; x<87;x++)
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
   //char *JWT_token = (char*)malloc(1+'.'+strlen(base64_header_claim)+strlen(base64_sign));                                    //Complete JWT Token  
  // char *JWT_token = (char*)malloc(1+'.'+strlen(base64_header_claim)+strlen(result)); 
 //  Serial.print("\nURL STRING ->           ");
 //  Serial.print(result);
//   int len = strlen(result);
//   Serial.print("\nSIGN STRING LEN ->");
//   Serial.print(len);
    char *JWT_token = (char*)malloc(1+'.'+strlen(base64_header_claim)+100);                                                      //65 is for ecdsa sign 
   //int sprintf_ret = sprintf(JWT_token, "%s.%s",base64_header_claim, base64_sign);
    int sprintf_ret = sprintf(JWT_token, "%s.%s",base64_header_claim, result);

 
    char *bearer_token = (char*)malloc(1+strlen(JWT_token)+strlen("Bearer ")); 
    sprintf(bearer_token,"%s%s","Bearer ", JWT_token);
    Serial.print("\nBearer token -> ");
    Serial.print(bearer_token);
    http.addHeader("Content-Type","application/json");
    http.addHeader("Authorization",bearer_token);                                                                             //Authorization set
    ret = http.POST(payload_data);
    Serial.print("\n HTTP Code ");                                          
    Serial.print(ret);
    String server_response = http.getString();
    Serial.print("\nServer response ");
    Serial.print(server_response);
   // Serial.print("\nCounter -> ");
   // Serial.print(counter);
 //   Serial.print("\n\n\n\n\n");
  
    free(bearer_token);
    free(JWT_token);
    free(base64_header_claim);
    free(claim);
    free(result);
 // }
 // while(ret != HTTP_SUCCESS);
   http.end();
    return 0;
}

int ECDSA_signature_det(const char *private_key, char* input_buffer, uint8_t* output_buffer)
  {
    int out_len = 0;
    int keypair = 0;
    int pk_cont = 0;
    int sign_verify = 0;
    mbedtls_ecdsa_context ecdsa_ctx; 
    mbedtls_pk_context pk_ctx;
    mbedtls_mpi r;
    mbedtls_mpi s;
     // do
     // {                                                 ///////////////Initialization    
        mbedtls_pk_init(&pk_ctx);
        mbedtls_ecdsa_init(&ecdsa_ctx);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_init(&r);
     //  Serial.print("\nINPUT BUFFER -> ");
     //   Serial.print(input_buffer);
     //   Serial.print("\nPRIVATE KEY -> ");
     //   Serial.print(private_key);
        pk_cont = mbedtls_pk_parse_key(&pk_ctx,(unsigned char*)private_key,strlen(private_key)+1, NULL, NULL);
  //      Serial.print("\nECDSA PRIVATE_KEY PARSE ->");
  //      Serial.print(pk_cont); 
        keypair = mbedtls_ecdsa_from_keypair(&ecdsa_ctx,mbedtls_pk_ec(pk_ctx));
  //      Serial.print("\nECDSA KEYPAIR ->");
  //      Serial.print(keypair);
        int verify = mbedtls_ecdsa_sign_det(&ecdsa_ctx.grp, &r,&s, &ecdsa_ctx.d ,(const unsigned char*)input_buffer, strlen(input_buffer), MBEDTLS_MD_SHA256);  
        int buffer_1 = mbedtls_mpi_write_binary(&r,(uint8_t*) output_buffer,32);
        int buffer_2 = mbedtls_mpi_write_binary(&s,(uint8_t*) output_buffer+32,32);
  //      Serial.print("\nECDA VERIFY ->");
  //      Serial.print(verify); 
  //      Serial.print("\nECDA BUFFERS ->");
  //      Serial.print(buffer_1);
  //      Serial.print(buffer_2); 
  //      Serial.print("\nECDA OUTPUT ->");
  //      for(int i = 0; i < 65; i++)
  //        {
  //           Serial.print((char)output_buffer[i]);
  //        } 
      /*  out_len = strlen((const char*)output_buffer);
        Serial.print("\nECDA OUT_LEN ->");
        Serial.print(out_len);
        char *sign = JWT_base_64_url(output_buffer);
        Serial.print("\nECDA BASE64_OUT_BUFF ->");
        Serial.print(sign); 
   */ 
   // }
    //while(out_len != 64);    
     mbedtls_pk_free(&pk_ctx); 
     mbedtls_ecdsa_free(&ecdsa_ctx );
     mbedtls_mpi_free(&r);
     mbedtls_mpi_free(&s); 
    //mbedtls_pk_free(&pk_ctx); 
  //  Serial.print("\nECDA EXIT -> -> -> ->");
   return 0; 
  }

int Encrypt_SHA256(const char *input_string,char *output_hash, char *output_hash_hex)
  {
  unsigned char test[32];     
 /*
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256; 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx,(unsigned char*)input_string, strlen(input_string));
  mbedtls_md_finish(&ctx,(unsigned char*)output_hash);
 // hash_ret = mbedtls_sha256_ret((const unsigned char*)output_hash,strlen(output_hash),test,0);
  */
  Serial.print("\nINPUT FOR SHA256 ->");
  Serial.print(input_string);
  int len_input = strlen(input_string);
  Serial.print("\nINPUT LEN FOR SHA256 ->");
  Serial.print(len_input);
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  int start_ret = mbedtls_sha256_starts_ret(&ctx,0);
  int update_ret = mbedtls_sha256_update_ret(&ctx,(unsigned char*)input_string, strlen(input_string));
  int finish_ret = mbedtls_sha256_finish_ret(&ctx,(unsigned char*)output_hash);
  int hash_ret = mbedtls_sha256_ret((const unsigned char*)output_hash,strlen(output_hash),test,0);
  int sha_len =strlen(output_hash);
  Serial.print("\nHASH FINISH RET SHA256 ->");      //must be 32!!!!!!!!!
  Serial.print(finish_ret);  
  Serial.print("\nHASH LEN IN SHA256 ->");      //must be 32!!!!!!!!!
  Serial.print(sha_len);  
  Serial.print("\nSHA256 RET -> ");
  Serial.print(hash_ret);
   Serial.print("\nSHA256 START -> ");
  Serial.print(start_ret);
  Serial.print("\nSHA256 UPDATE -> ");
  Serial.print(update_ret);
  Serial.print("\nSHA256 FINISH -> ");
  Serial.print(finish_ret);
  Serial.print("\nSHA256 RET -> ");
  Serial.print(hash_ret);
     for(int i= 0; i< (strlen(output_hash)); i++)   
     sprintf(output_hash_hex+(i*2), "%02x",output_hash[i]);
  Serial.print("\nHASH SHA256 HEX ->");      //32!!!!!!!!!
  Serial.print(output_hash_hex);
  mbedtls_sha256_free(&ctx);
//  mbedtls_md_free(&ctx);
  if(sha_len == 32)
    return 0;
  else  
    return 1;


 
  //zfor(int i= 0; i<((strlen(output_hash)-2)*2); i++)     
  //for(int i= 0; i< (strlen(output_hash)); i++)    


   
 // mbedtls_md_free(&ctx);
  }

void LocalTime()
{
  struct tm timeinfo;
  if(!getLocalTime(&timeinfo)){   
    Serial.println("Failed to obtain time");
    return;
  }
  Serial.println(&timeinfo, "%H:%M:%S");
  Serial.println("Timestamp: ");
  time_t timestamp;
  time(&timestamp);
  //timestamp +=SEC_TO_EXPIRE;
}



char *JWT_base_64_url(char* base_str)   
{
  int x =0;
  int olen =0;
  uint8_t *base_unsigned = (uint8_t*)base_str; 
 // Serial.print("\nBASE64 INPUT ->");
 // Serial.print(base_str);
  String out = base64::encode((uint8_t*)base_unsigned,strlen((const char*)base_unsigned));
 // Serial.print("\nBASE64 SPOJENY STRING -> ");
 // Serial.print((char*)base_unsigned);
  char *result = (char*)malloc(out.length()+1);
  strcpy(result,out.c_str()); 
  for(x =0 ; x<(strlen(result));x++)
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
//   Serial.print("\nBASE64 ->");
//   Serial.print(result);
    return result;
    free(result);
    free(base_unsigned);
}
