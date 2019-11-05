import ipaddress
import socket
from myiputils import *


class CamadaRede:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.meu_endereco = None

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
            if ttl > 1:
                datagrama = make_ipv4_header(src_addr, dst_addr, payload, ttl - 1)
                self.enlace.enviar(datagrama, next_hop)
            else:
                datagrama = make_ipv4_header(self.meu_endereco, src_addr, payload, error = True)
                icmp_packet = self.__send_time_exceeded_request(datagrama, payload)
                self.enlace.enviar(datagrama, next_hop)

    def __send_time_exceeded_request(self, ip_header, payload):
        iptype = 11
        code = (0 << 8)
        checksum = 0
        pseudo = struct.pack('!BB', iptype, code) + ip_header + payload[8:]
        checksum = calc_checksum(pseudo)
        pack = struct.pack('!BB', iptype, code) + ip_header + payload[8:]
        return pack

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        compatible_cidrs = []
        for CIDR, hop in self.tabela:
            if self.__is_in_cidr(CIDR, dest_addr):
                compatible_cidrs.append((CIDR, hop))
        if len(compatible_cidrs) == 0:
            return None
        elif len(compatible_cidrs) > 1:
            return self.__select_best_hop(compatible_cidrs)
        else:
            return compatible_cidrs.pop()[1]

    def __select_best_hop(self, cidr_list):
        largest_range = int(cidr_list[0][0].split('/')[1])
        best_hop = cidr_list[0][1]
        for cidr, hop in cidr_list:
            range = int(cidr.split('/')[1])
            if range > largest_range:
                largest_range = range
                best_hop = hop
        return best_hop

    def __is_in_cidr(self, cidr, ip):
        network = ipaddress.IPv4Network(cidr)
        first, last = str(network[0]), str(network[-1])
        ip, first, last = str2addr(ip), str2addr(first), str2addr(last)
        return ip >= first and ip <= last

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela
        pass

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.
        datagrama = make_ipv4_header(self.meu_endereco, dest_addr, segmento)
        self.enlace.enviar(datagrama, next_hop)

def make_ipv4_header(src_addr, dest_addr, payload, ttl = 64, **kwargs):
    # https://en.wikipedia.org/wiki/IPv4#Header
    # min header size = 16 octets / 126 bytes
    # Default values
    # 1st octet
    ver = (4 << 4)
    ihl = 5
    # 2nd octet
    dscp = ecn = 0
    # 3rd octet
    header_len = 20 + len(payload)
    # 4th octet
    identification = 0
    # 5th octet
    flags = (0 << 13)
    # ttl: 6th octet
    # 7th octet
    if "error" in kwargs and kwargs["error"]:
        proto = IPPROTO_ICMP
    else:
        proto = IPPROTO_TCP
    # 8th & 9th octet
    checksum = 0
    # 10th to 12th octet
    src_addr = socket.inet_aton(src_addr)
    # 13th to 16th octet
    dest_addr = socket.inet_aton(dest_addr)
    pseudo = struct.pack('!BBHHHBBH4s4s', ver + ihl, dscp + ecn, header_len, identification, \
        flags, ttl, proto, checksum, src_addr, dest_addr)
    checksum = calc_checksum(pseudo[:4*ihl])
    pack = struct.pack('!BBHHHBBH4s4s', ver + ihl, dscp + ecn, header_len, identification, \
        flags, ttl, proto, checksum, src_addr, dest_addr) + payload
    return pack
