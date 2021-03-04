#ifndef JTW_H
#define JWT_H

#include <Arduino.h>

char *JWT_base_64_url(char *base_str);
void LocalTime();
int Encrypt_SHA256(const char *input_string, char *output_hash, char *output_hash_hex);
int ECDSA_signature_det(const char *private_key, char* input_buffer, uint8_t* output_buffer);
int Send_to_server(const char *private_key, const char *public_key, int sec_to_expire, const char *serial_num, char *end_point, char *payload_data);

#endif 
