

// Oppstart og initiering
int main(int argc, char *argv[]);
void init_unix_socket(const char *path);
void init_mip_socket(const char *path);

// Håndtering av applikasjoner
void handle_new_app_connection();
void handle_app_message(int app_fd);

// Håndtering av mottatte MIPTP-pakker
void handle_incoming_miptp_packet(uint8_t *buf, size_t len, uint8_t src_mip);

// Sendefunksjoner
void send_miptp_data(...);
void send_miptp_ack(...);

// Tidsstyring / retransmisjon
void check_retransmissions();

// Hjelpefunksjoner
uint16_t pack_seq_pad(uint16_t seq, uint8_t padlen);
void unpack_seq_pad(uint16_t seq_pad, uint16_t *seq, uint8_t *padlen);
