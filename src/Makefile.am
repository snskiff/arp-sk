include $(top_srcdir)/Makefile.am.common

INCLUDES = @NETINC@ @COMPATINC@ 

sbin_PROGRAMS = arp-sk

arp_sk_SOURCES=sk.c \
        lookup-eth-ip.c \
        signal.c \
        send-packet.c \
        arp-eth-ip.c \
        arp-common.c \
        eth-common.c \
        ip-common.c \
	arp-sk.c


arp_sk_LDADD = @NETLIB@ @COMPATLIB@


DISTCLEANFILES = *~
