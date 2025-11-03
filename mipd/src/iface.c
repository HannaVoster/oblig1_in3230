#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <ifaddrs.h>
#include <unistd.h>     
#include <arpa/inet.h>  

#include "iface.h"
#include "mipd.h"

int iface_indices[5];
int iface_count = 0;
char iface_name[MAX_IFACES][IFNAMSIZ];

/*
Finner alle aktive nettverksgrensesnitt på maskinen (unntatt loopback "lo") 
og lagrer navn og ifindex (interface-indeks) for hvert i de globale listene iface_name[] 
og iface_indices[] 

Disse brukes senere for å sende og motta MIP-pakker via riktige nettverkskort

Globalt resultat:
    -iface_name[] og iface_indices[] fylles ut
    -iface_count oppdateres
*/
void find_all_ifaces() {
    struct ifaddrs *ifaddr, *ifa;
    iface_count = 0;

    // Henter systemets liste over nettverksgrensesnitt
    getifaddrs(&ifaddr);

    // Henter kun fysiske grensesnitt (AF_PACKET), ikke lo eller IPv4/IPv6
    for (ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        if (ifa->ifa_addr->sa_family == AF_PACKET &&
            strcmp(ifa->ifa_name, "lo") != 0) {
            
            // Hent interface-indeksen
            int ifindex = if_nametoindex(ifa->ifa_name);

            // Lagre både navn og indeks i globale arrays
            iface_indices[iface_count] = ifindex;
            strncpy(iface_name[iface_count], ifa->ifa_name, IFNAMSIZ);

            if (debug_mode)
                printf("[DEBUG] Found interface %s (index=%d)\n",
                       iface_name[iface_count], iface_indices[iface_count]);

            iface_count++;
        }
    }
    // Frigjør minnet allokert av getifaddrs()
    freeifaddrs(ifaddr);
}


/*
Denne funksjonen tar inn navnet på et nettverksinterface, 
oppretter en socket for å spørre kjernen om informasjon, 
og bruker ioctl med flagget SIOCGIFHWADDR for å hente MAC-adressen. 

Resultatet kopieres til bufferet mac. Den returnerer 0 hvis alt gikk bra, ellers -1

brukes av send_pdu i pdu.c
*/
int get_iface_mac(const char *ifname, unsigned char *mac) {

    // Åpner en socket for å kunne utføre ioctl-kall på interfacet
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

    // Henter hardware-adressen (MAC) via ioctl
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        close(fd);
        return -1;
    }

    memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    close(fd);
    return 0;
}

/*
-create_raw_socket
lager en råsocket for å sende og motta MIP-pakker direkte over Ethernet. 
funksjonen binder socketen til det valgte nettverksinterface, 
og returnerer filbeskriveren. Programmet avsluttes hvis noe går galt
*/
int create_raw_socket() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_MIP));
    if (sock < 0) {
        perror("raw socket");
        exit(EXIT_FAILURE);
    }

    // Ikke bind til ett interface – da lytter den på alle
    if (debug_mode) {
        printf("[DEBUG] create_raw_socket: global listener for proto=0x%X\n\n", ETH_P_MIP);
    }

    return sock;
}