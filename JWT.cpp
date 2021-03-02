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
  char *key_hex = "73c326f9669e369662fe3ce1fabf9df32cc87eca0780795c4773fedd4f57f9b5";/////////////////////////////////////////////////////////////////////////////////Test - JWT prejde na server, ale mne generuje jwt inak ako Viktorovi 
  int ret = 0;
  char sha_pub_key[65]={0};
  char sha_pub_key_hex[65]={0};
  
  char hash_string[65]={0}; 
  char hash_string_test[65]={0};
  //char output_buffer_hex[32] ={0};
  time_t time_iat,time_exp;
  struct tm timeinfo;

  while(ret != HTTP_SUCCESS)
  {
  //Encrypt_SHA256(public_key,&sha_pub_key[0],&sha_pub_key_hex[0]);               //generate kid (public key hash sha256 in hex)    // not in use yet
    char *header = (char*) malloc(1+strlen("{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":}")+strlen(key_hex));
    sprintf(header,"{\"alg\":\"ES256\",\"typ\":\"JWT\",\"kid\":\"%s\"}",key_hex);
    char *vysledok_header = JWT_base_64_url(header);                              //Header in BASE64_URL  //free
  
   time(&time_iat);
   time_exp = time_iat + sec_to_expire;
   char *claim = (char*) malloc(25+strlen((const char*)("{\"sub\":\"%s\",\"iat\":%d,\"exp\":%d}"))+strlen(serial_num)+strlen((const char*)time_iat)+strlen((const char*)time_exp));  //free
   sprintf(claim,"{\"sub\":\"%s\",\"iat\":%lu,\"exp\":%lu}",serial_num,time_iat,time_exp);
   char *vysledok_claim = JWT_base_64_url(claim); 
   char *base64_header_claim = (char*) malloc(1+strlen((const char*)".")+strlen(vysledok_claim)+strlen(vysledok_header));     ///////////header+claim -> JWT Content    //free
   sprintf(base64_header_claim,"%s.%s",vysledok_header,vysledok_claim);
   Encrypt_SHA256(base64_header_claim,&hash_string[0],&hash_string_test[0]); 
   char output_buffer_hex[65] ={0};
   ECDSA_signature_det(private_key,hash_string,&output_buffer_hex[0]);
   char *base64_sign = JWT_base_64_url(output_buffer_hex);      
   //Serial.print("\nBase64_sign ->");
   //Serial.print(output_buffer_hex);              
   char *JWT_token = (char*)malloc(1+'.'+strlen(base64_header_claim)+strlen(base64_sign));  //free
   int sprintf_ret = sprintf(JWT_token, "%s.%s",base64_header_claim, base64_sign);

    HTTPClient http;
    http.begin(end_point);
    char *bearer_token = (char*)malloc(1+strlen(JWT_token)+strlen("Bearer ")); //free
    sprintf(bearer_token,"%s%s","Bearer ", JWT_token);
   // Serial.print("\nBearer token -> ");
   // Serial.print(bearer_token);
   // Serial.print("\nDef token -> ");
   // Serial.print(token);
    http.addHeader("Content-Type","application/json");
    http.addHeader("Authorization",bearer_token);       
    ret = http.POST(payload_data);
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
  }
    return 0;
}

int ECDSA_signature_det(const char *private_key, char* input_buffer, char* output_buffer)
  {
    int out_len = 0;
    int keypair = 0;
    mbedtls_ecdsa_context ecdsa_ctx; 
    mbedtls_pk_context pk_ctx;
    mbedtls_mpi s,r;
     // do
     // {                                                 ///////////////Initialization          
        mbedtls_pk_init(&pk_ctx);
        mbedtls_ecdsa_init(&ecdsa_ctx);
        mbedtls_mpi_init(&s);
        mbedtls_mpi_init(&r);
        int pk_cont = mbedtls_pk_parse_key(&pk_ctx,(unsigned char*)private_key,strlen(private_key)+1, NULL, NULL);
        Serial.print("\nECDSA PRIVATE_KEY PARSE ->");
        Serial.print(pk_cont); 
        keypair = mbedtls_ecdsa_from_keypair(&ecdsa_ctx,mbedtls_pk_ec(pk_ctx));
        Serial.print("\nECDSA KEYPAIR ->");
        Serial.print(keypair);
       
        int verify = mbedtls_ecdsa_sign_det(&ecdsa_ctx.grp, &r,&s, &ecdsa_ctx.d ,(const unsigned char*)input_buffer, strlen(input_buffer), MBEDTLS_MD_SHA256);  
        int buffer_1 = mbedtls_mpi_write_binary(&r,(unsigned char*) output_buffer,32);
        int buffer_2 = mbedtls_mpi_write_binary(&s,(unsigned char*) output_buffer+32,32);
        Serial.print("\nECDA VERIFY ->");
        Serial.print(verify); 
        Serial.print("\nECDA BUFFERS ->");
        Serial.print(buffer_1);
        Serial.print(buffer_2); 
        out_len = strlen(output_buffer);
        Serial.print("\nECDA OUT_LEN ->");
        Serial.print(out_len);
        char *sign = JWT_base_64_url(output_buffer);
        Serial.print("\nECDA BASE64_OUT_BUFF ->");
        Serial.print(sign); 
   // }
    //while(out_len != 64);    
     mbedtls_pk_free(&pk_ctx); 
     mbedtls_ecdsa_free(&ecdsa_ctx );
     mbedtls_mpi_free(&r);
     mbedtls_mpi_free(&s); 
    //mbedtls_pk_free(&pk_ctx); 
    //for(int i= 0; i< sizeof(output_buffer); i++)                
    //sprintf(&output_buffer_hex[i*2], "%02x",output_buffer[i]);
    Serial.print("\nECDA EXIT -> -> -> ->");
   return 0;
  }

int Encrypt_SHA256(const char *input_string,char *output_hash, char *output_hash_hex)
  {
  mbedtls_md_context_t ctx;
  mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256; 
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(md_type), 0);
  mbedtls_md_starts(&ctx);
  mbedtls_md_update(&ctx,(unsigned char*) input_string, strlen(input_string));
  mbedtls_md_finish(&ctx,(unsigned char*) output_hash);
  //for(int i= 0; i<((strlen(output_hash)-2)*2); i++)     
  for(int i= 0; i< (strlen(output_hash)); i++)         
      sprintf(output_hash_hex+(i*2), "%02x",output_hash[i]);
  mbedtls_md_free(&ctx);
  return 0;
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



char *JWT_base_64_url(char *base_str)   
{
  int x =0;
  int len =0;
  int olen =0;
  String str_base64 = base_str;
  String out = base64::encode((str_base64));
  const char *str = out.c_str();
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
   Serial.print("\nBASE64 ->");
   Serial.print(result);
    return result;
    free(result);
}



/*
char *JWT_base_64_url(char *base_str)   
{
   char *out;
	//size_t*  elen;
	//size_t*  i;
	//size_t*  j;
	//size_t*  v;
  //size_t len;
  
  int elen,i,j,v,len;
  len = strlen(base_str);
  if (base_str == NULL || len == 0)
		while(1);
  elen = len;
  if(len % 3 != 0)
    elen += 3- (len%3);
  elen /= 3;
  elen *= 4;
  out  = (char*) malloc(elen+1);
	out[elen+1] = '\0'; 
   Serial.print("\nLEN_sign ->");
   int lenlen = strlen(out);
   Serial.print(lenlen); 
  int x =0;

  	for (i=0, j=0; i<len; i+=3, j+=4) {
		v = base_str[i];
		v = i+1 < len ? v << 8 | base_str[i+1] : v << 8;
		v = i+2 < len ? v << 8 | base_str[i+2] : v << 8;

		out[j]   = b64chars[(v >> 18) & 0x3F];
		out[j+1] = b64chars[(v >> 12) & 0x3F];
		if (i+1 < len) {
			out[j+2] = b64chars[(v >> 6) & 0x3F];
		} else {
			out[j+2] = '=';
		}
		if (i+2 < len) {
			out[j+3] = b64chars[v & 0x3F];
		} else {
			out[j+3] = '=';
		}
	}
 for(x; x<(strlen(out));x++)
  {
   char c = *(out+x);
   switch(c)
   {
     case '+' : *(out+x) = '-';
                 break;
    case '/' :  *(out+x) = '_';
                break;
    case '=' :  *(out+x) = NULL;
                break; 
    default : break;
  }
  }
   Serial.print("\nLOOP ->");
   Serial.print(x);
  
    return out;
    free(out);
}*/
