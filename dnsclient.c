/*BOMPA REMUS 325CB*/
  #include<stdio.h>
  #include <stdlib.h>
  #include <string.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <unistd.h>

  #define A 1
  #define NS 2
  #define CNAME 5
  #define MX 15
  #define SOA 6
  #define TXT 16
  #define PTR 12
  #define BUFLEN 256

  void afi_compressed_name (char **buffer, char *base_buffer, FILE * file);
  void afi_name (char **buffer, char *base_buffer, FILE * file);

  void
  error (char *msg)
  {
    perror (msg);
    exit (0);
  }

  //setare bit
  void
  set_bit (char *c, int pos)
  {
    char mask = 1 << (7 - pos);
    (*c) |= mask;
  }

  //stergere bit
  void
  unset_bit (char *c, int pos)
  {
    char mask = ~(1 << (7 - pos));
    (*c) &= mask;
  }

  //afiseaza un bit
  unsigned int
  get_bit (unsigned char c, int pos)
  {
    return (c >> (7 - pos)) % 2;
  }

  //creare header mesaj
  void
  make_query (char *buffer, unsigned short id)
  {
    //make header
    unsigned short id_big = htons (id);
    memcpy (buffer, &id_big, 2);
    unset_bit (buffer + 2, 0);	//qr =>0-query
    //opcode =>0-standard query
    unset_bit (buffer + 2, 1);
    unset_bit (buffer + 2, 2);
    unset_bit (buffer + 2, 3);
    unset_bit (buffer + 2, 4);
    //aa nu conteaza in query
    unset_bit (buffer + 2, 5);
    //tc =>0- nu e trunchiat
    unset_bit (buffer + 2, 6);
    //rd
    set_bit (buffer + 2, 7);
    //ra
    unset_bit (buffer + 3, 0);
    //z
    unset_bit (buffer + 3, 1);
    unset_bit (buffer + 3, 2);
    unset_bit (buffer + 3, 3);
    //rcode =>ptr response
    unset_bit (buffer + 3, 4);
    unset_bit (buffer + 3, 5);
    unset_bit (buffer + 3, 6);
    unset_bit (buffer + 3, 7);
    //qdcount
    memset (buffer + 4, 0, 2);
    //ancount
    memset (buffer + 6, 0, 2);
    //nscount
    memset (buffer + 8, 0, 2);
    //arcount
    memset (buffer + 10, 0, 2);
  }

  //memoreaza in buffer, domain_name sub forma de secventa de label-uri
  unsigned short
  labelled_name (char *buffer, char *domain_name)
  {
    char len = 0;			//lungimea unui label
    int i;
    int bufi = 0;			//pozitia care a ramas nescrisa in buffer
    for (i = 0; i <= strlen (domain_name); i++)
      {
        //se termina un label
        if (domain_name[i] == '.' || i == strlen (domain_name))
    {
      memcpy (buffer + bufi, &len, 1);
      memcpy (buffer + bufi + 1, domain_name + i - len, len);
      bufi = bufi + 1 + len;
      len = 0;
      //se continua intr-un label
    }
        else
    {
      len++;
    }
      }
    buffer[bufi] = 0;		//domeniul root
    return bufi + 1;
  }

  //inversare adresa IP si adaugare sir ".in-addr.arpa" la finalul ei
  int
  reverse_name (char *domain_name)
  {
    int i;
    struct in_addr addr;
    int r = inet_aton (domain_name, &addr);
    if (r == 0)
      {
        printf ("Format adresa ipv4 invalid !\n");
        return -1;
      }
    //inversare adresa ipv4 din domain_name
    for (int i = 3; i >= 0; i--)
      {
        sprintf (domain_name, "%hhu.", ((char *) &addr.s_addr)[i]);
        domain_name += strlen (domain_name);
      }
    //adaugare "in-addr.arpa" la finalul adresei inversate
    sprintf (domain_name, "in-addr.arpa");
    return 0;
  }

  //adauga o interogare header-ului unui mesaj
  unsigned short
  add_question (char *buffer, char *domain_name, unsigned short type)
  {
    //se incrementeaza campul mesajului care indica numarul de interogari: qdcount
    unsigned short qdcount = ntohs (*((unsigned short *) (buffer + 4)));
    qdcount = htons (++qdcount);
    memcpy (((unsigned short *) (buffer + 4)), &qdcount, 2);
    //memorare qname sub forma de secventa de label-uri
    buffer += 12;
    unsigned short nr = labelled_name (buffer, domain_name);
    //qtype se seteaza pe type primit ca parametru
    unsigned short type_big = htons (type);
    memcpy (buffer + nr, &type_big, 2);
    //qclass se seteaza pe 1 (IN => internet)
    unsigned short class_big = htons (1);
    memcpy (buffer + nr + 2, &class_big, 2);
    return 12 + nr + 4;
  }

  //scrie mesajul in message.log 
  void
  write_message (char *buffer, char *end_buffer, FILE * file)
  {
    int first = 0;
    while (buffer != end_buffer)
      {
        if (first == 1)
    fprintf (file, " ");
        fprintf (file, "%02x", *buffer);
        buffer++;
        first = 1;
      }
    fprintf (file, "\n");
  }

  //afiseaza un nume comprimat ca un nume de domeniu
  void
  afi_compressed_name (char **buffer, char *base_buffer, FILE * file)
  {
    //aflare pozitie in buffer a numelui
    unsigned short index = ntohs (*((unsigned short *) (*buffer)));
    (*buffer) += 2;
    index <<= 2;
    index >>= 2;
    char *aux = base_buffer + index;
    //se afiseaza numele spre care indica numele comprimat
    afi_name (&aux, base_buffer, file);
  }

  //afiseaza un nume salvat in *buffer sub forma de sir de label-uri si/sau comprimat ca un nume de domeniu
  void
  afi_name (char **buffer, char *base_buffer, FILE * file)
  {
    while (1)
      {
        if (get_bit (*(*buffer), 0) == 1 && get_bit (*(*buffer), 1) == 1)
    {			//verificare daca numele este comprimat
      afi_compressed_name (buffer, base_buffer, file);
      return;
    }
        unsigned char len = *(*buffer);
        (*buffer)++;
        int j;
        for (j = 1; j <= len; j++)
    {
      fprintf (file, "%c", *(*buffer));
      (*buffer)++;
    }
        char left = *(*buffer);
        fprintf (file, ".");
        if (left == 0)
    break;
      }
    (*buffer)++;			//sar peste 0
  }

  //afisarea clasei unei inregistrari
  void
  afi_class (unsigned short class, FILE * file)
  {
    switch (class)
      {
      case 1:
        fprintf (file, "IN ");
        break;
      case 2:
        fprintf (file, "CS ");
        break;
      case 3:
        fprintf (file, "CH ");
        break;
      case 4:
        fprintf (file, "HS ");
        break;
      }
  }

  //afisarea tipului unei inregistrari
  void
  afi_type (unsigned short type, FILE * file)
  {
    switch (type)
      {
      case A:
        fprintf (file, "A ");
        break;
      case NS:
        fprintf (file, "NS ");
        break;
      case CNAME:
        fprintf (file, "CNAME ");
        break;
      case SOA:
        fprintf (file, "SOA ");
        break;
      case PTR:
        fprintf (file, "PTR ");
        break;
      case MX:
        fprintf (file, "MX ");
        break;
      case TXT:
        fprintf (file, "TXT ");
        break;
      }
  }

  //asociaza tipul primit ca parametru cu numarul corespunzator unuia dintre tipurile 
  //definite la inceput: A,NS,CNAME,SOA,PTR,MX,TXT
  unsigned short
  get_type (char *type)
  {
    if (!strcmp (type, "A"))
      return A;
    else if (!strcmp (type, "NS"))
      return NS;
    else if (!strcmp (type, "CNAME"))
      return CNAME;
    else if (!strcmp (type, "SOA"))
      return SOA;
    else if (!strcmp (type, "PTR"))
      return PTR;
    else if (!strcmp (type, "MX"))
      return MX;
    else if (!strcmp (type, "TXT"))
      return TXT;
    return 0;
  }

  //afiseaza un raspuns de la server
  void
  show_response (char *buffer, char *base_buffer, char *end_buffer, FILE * file)
  {
    unsigned short ancount = ntohs (*((unsigned short *) (base_buffer + 6)));	//nr de inregistrari din ANSWER
    unsigned short nscount = ntohs (*((unsigned short *) (base_buffer + 8)));	//nr de inregistrari din AUTHORITY
    unsigned short arcount = ntohs (*((unsigned short *) (base_buffer + 10)));	//nr de inregistrari din ADDITIONAL
    unsigned short i = 0;
    if (ancount + nscount + arcount > 0)
      fprintf (file, "\n");	//daca exista cel putin o inregistrare
    //se lasa un rand liber intre comanda
    //si inregistrari
    while (buffer != end_buffer)
      {
        if (i == 0 && ancount != 0)
    fprintf (file, ";; ANSWER SECTION:\n");
        else if (i == ancount && nscount != 0)
    fprintf (file, ";; AUTHORITY SECTION:\n");
        else if (i == ancount + nscount)
    fprintf (file, ";; ADDITIONAL SECTION:\n");
        i++;
        //afisare name
        afi_name (&buffer, base_buffer, file);
        unsigned short type = ntohs (*((unsigned short *) (buffer)));
        buffer += 2;
        unsigned short class = ntohs (*((unsigned short *) (buffer)));
        buffer += 2;
        fprintf (file, " ");
        afi_class (class, file);
        afi_type (type, file);
        //ttl
        unsigned int ttl = ntohl (*((unsigned int *) (buffer)));
        buffer += 4;
        //rdlen
        unsigned short rdlen = ntohs (*((unsigned short *) (buffer)));
        buffer += 2;
        //rdata
        switch (type)
    {
    case A:
      {
        //afisare adrese IP 
        char *end_addr = buffer + rdlen;
        int prev = 0;
        while (buffer != end_addr)
          {
      if (prev == 1)
        fprintf (file, ",");	//daca a mai fost un string inainte
      //se afiseaza o virgula inainte de 
      //urmatorul string
      struct in_addr addr_n;
      memcpy (&(addr_n.s_addr), buffer, 4);
      buffer += 4;
      fprintf (file, "%s", inet_ntoa (addr_n));
      prev = 1;
          }
        break;
      }
    case NS:
      //afisare NameServer
      afi_name (&buffer, base_buffer, file);
      break;
    case CNAME:
      //afisare PrimaryName
      afi_name (&buffer, base_buffer, file);
      break;
    case SOA:
      //afisare mname
      afi_name (&buffer, base_buffer, file);
      fprintf (file, " ");
      //afisare rname
      afi_name (&buffer, base_buffer, file);
      unsigned int serial = ntohl (*((unsigned int *) (buffer)));
      buffer += 4;
      fprintf (file, " %d", serial);

      unsigned int refresh = ntohl (*((unsigned int *) (buffer)));
      buffer += 4;
      fprintf (file, " %d", refresh);

      unsigned int retry = ntohl (*((unsigned int *) (buffer)));
      buffer += 4;
      fprintf (file, " %d", retry);

      unsigned int expiration = ntohl (*((unsigned int *) (buffer)));
      buffer += 4;
      fprintf (file, " %d", expiration);

      unsigned int minimum = ntohl (*((unsigned int *) (buffer)));
      buffer += 4;
      fprintf (file, " %d", minimum);
      break;

    case PTR:
      //afisare addr
      afi_name (&buffer, base_buffer, file);
      break;
    case MX:
      {
        unsigned short preference =
          ntohs (*((unsigned short *) (buffer)));
        buffer += 2;
        fprintf (file, "%hu ", preference);
        //afisare mailExchange
        afi_name (&buffer, base_buffer, file);
        break;
      }
    case TXT:
      {
        //afisare siruri de mesaje
        char *end_text = buffer + rdlen;
        int prev = 0;
        while (buffer != end_text)
          {
      if (prev == 1)
        fprintf (file, ",");	//daca a mai fost un string inainte
      //se afiseaza o virgula inainte de 
      //urmatorul string
      char txtdata[BUFLEN];
      char txtlen;
      memcpy (&txtlen, buffer, 1);
      buffer++;
      txtdata[0] = '"';
      memcpy (txtdata + 1, buffer, txtlen);
      buffer += txtlen;
      txtdata[1 + txtlen] = '"';
      txtdata[2 + txtlen] = 0;
      fprintf (file, "%s", txtdata);
      prev = 1;
          }
        break;
      }

    }
        fprintf (file, "\n");	//finalul afisarii unei inregistrari
      }
  }

  int
  main (int argc, char *argv[])
  {
    //verificare numar de parametri egal cu 2
    if (argc != 3)
      {
        fprintf (stderr, "Usage %s domain_name/IP query_type\n", argv[0]);
        return 0;
      }
    //verificare tip valid
    unsigned short type = get_type (argv[2]);
    if (type == 0)
      {
        printf ("Tip de interogare invalid!\n");
        return 0;
      }

    unsigned short id = 0;
    char domain_name[BUFLEN];
    strcpy (domain_name, argv[1]);
    //daca tipul de interogare e PTR
    if (type == 12)
      {
        if (reverse_name (domain_name) < 0)
    return 0;
      }
    FILE *dns_servers = fopen ("dns-servers.conf", "r");
    FILE *message_log = fopen ("message.log", "a");
    FILE *dns_log = fopen ("dns.log", "a");
    while (1)
      {
        //citire ip server din dns_servers.conf
        char ip_server[BUFLEN];
        if (fgets (ip_server, BUFLEN, dns_servers) == NULL)
    break;;
        if (ip_server[0] == '#')
    continue;
        //stabilire conexiune tcp cu serverul
        ip_server[strlen (ip_server) - 1] = 0;
        int sockfd = socket (AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0)
    error ("ERROR opening socket");
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        char port[3];
        sprintf (port, "53");
        serv_addr.sin_port = htons (atoi (port));
        inet_aton (ip_server, &serv_addr.sin_addr);
        //in caz de eroare la comunicare, se incearca alt server
        if (connect (sockfd, (struct sockaddr *) &serv_addr, sizeof (serv_addr))
      < 0)
    {
      printf ("ERROR connecting %s a\n", ip_server);
      continue;
    }

        char sent_message[BUFLEN];
        char *buffer = sent_message + 2;	//alocare spatiu pentru len
        memset (sent_message, 0, BUFLEN);
        //creare header
        make_query (buffer, id);
        id++;
        //crearea sectiune question
        unsigned short size = add_question (buffer, domain_name, type);
        size = htons (size);
        //se adauga dimensiunea la inceputul mesajului
        memcpy (sent_message, &size, 2);
        //trimit mesaj la server
        size = ntohs (size);
        int n = send (sockfd, sent_message, size + 2, 0);
        if (n < 0)
    {
      error ("ERROR writing to socket");
    }

        char received_message[BUFLEN];
        memset (received_message, 0, BUFLEN);
        if ((n = recv (sockfd, received_message, BUFLEN, 0)) <= 0)
    {
      error ("ERROR reading to socket");
    }

        //verificare daca se obtine eroare de la server
        unsigned char rcode;
        buffer = received_message + 2;
        memcpy (&rcode, buffer + 3, 1);
        rcode = rcode << 4;
        rcode = rcode >> 4;
        if (rcode == 5 || rcode == 4 || rcode == 2)
    continue;
        else if (rcode == 3)
    {
      printf ("Nume domeniu inexistent!\n");
      break;
    }
        else if (rcode == 1)
    {
      printf ("Eroare format!\n");
      break;
    }

        unsigned short response_size =
    ntohs (*((unsigned short *) (received_message)));
        fseek (dns_log, 0, SEEK_END);
        int sz = ftell (dns_log);
        fseek (dns_log, 0, SEEK_SET);
        if (sz != 0)
    fprintf (dns_log, "\n\n");	//daca nu e prima comanda, si fisierul
        //nu e gol se lasa doua linii libere
        fprintf (dns_log, "; %s - %s %s\n", ip_server, argv[1], argv[2]);
        //scriere mesaj in message.log
        write_message (sent_message + 2, sent_message + 2 + size, message_log);
        //scriere raspuns in dns.log
        show_response (buffer + size, buffer, buffer + response_size, dns_log);


        close (sockfd);
        break;
      }
    fclose (dns_servers);
    fclose (message_log);
    fclose (dns_log);
    return 0;
  }
