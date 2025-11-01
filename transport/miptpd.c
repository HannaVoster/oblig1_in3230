/*
Hovedprogram til miptpd

main funksjon og event loop

**Ansvar:**

- Initialisere UNIX- og MIP-sockets (kalle `init_unix_socket()` og `init_mip_socket()`)
- Holde `select()`eller `poll()`løkken, EPOLL???
- Kalle de riktige handlerne (f.eks. `handle_app_message()`, `handle_incoming_miptp_packet()`)
- Holde oversikt over forbindelser (`connections[]`, porter osv.)
- Starte periodiske retransmisjonssjekker

*/