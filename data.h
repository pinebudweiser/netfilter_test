#include <stdint.h>

#pragma pack(push,1)	// Change default padding to 1Byte
typedef struct Ethernet{
        uint8_t DstMAC[6];
        uint8_t SrcMAC[6];
        uint16_t EType;
}ETH;	// DIX 2.0, 14Byte
typedef struct InternetProtocol{
        uint8_t IHL:4;
        uint8_t VER:4;
        uint8_t UnUse1;
        uint16_t TotalLength;
        uint32_t UnUse2;
        uint8_t UnUse3;
        uint8_t ProtocolID;
        uint16_t UnUse4;
        uint32_t SrcIP;
        uint32_t DstIP;
        uint8_t Option[0]; // ((IHL)<<2)
}IP;
typedef struct TransControlProtocol{
        uint16_t SrcPort;
        uint16_t DstPort;
        uint32_t UnUse1[2];
        uint8_t HeaderLength:4;
        uint8_t Reserved:4;
        uint8_t UnUse[0]; // (HeaderLength<<2) - BASIC_TCP_HEADER_SUB, 13Byte
}TCP;
#pragma pack(pop)
