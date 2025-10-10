#ifndef IFACE_H
#define IFACE_H

extern int iface_indices[5];
extern int iface_count;

int get_iface_mac(const char *ifname, unsigned char *mac);
void find_all_ifaces(void);

#endif