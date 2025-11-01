// håndtering av UNIX domain sockets (apper)
//fungerer som grensesnitt mot applikasjonene, laget over, øverste lag

/*
**Ansvar:**

- Opprette og lytte på UNIX domain socket
- Akseptere nye apper som kobler til (`accept()`)
- Motta og sende PDU-er til apper i riktig format:

[MIP address][port][payload]

*/
#include <stdint.h>
#include <stdlib.h>

int init_unix_socket(const char *path);
void handle_new_app_connection(int unix_fd);
void handle_app_message(int app_fd);