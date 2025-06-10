#pragma once

#include <arpa/inet.h>
#include <cstdint>

#pragma pack(push, 1)
struct TlsRecordHdr {
    uint8_t content_type_;
    uint16_t version_;
    uint16_t length_;

    uint16_t len() const { return ntohs(length_); }
    uint8_t type() const { return content_type_; }
    uint16_t version() const { return ntohs(version_); }

    bool is_tls() const {
        uint16_t ver = version();
        return (ver == 0x0301 || ver == 0x0302 || ver == 0x0303 || ver == 0x0304);
    }

    enum: uint8_t {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23
    };
};

struct TlsHandshakeHdr {
    uint8_t handshake_type_;
    uint8_t length_[3];

    uint8_t type() const { return handshake_type_; }

    uint32_t len() const {
        return (length_[0] << 16) | (length_[1] << 8) | length_[2];
    }

    enum: uint8_t {
        HelloRequest = 0,
        ClientHello = 1,
        ServerHello = 2,
        Certificate = 11,
        ServerKeyExchange = 12,
        CertificateRequest = 13,
        ServerHelloDone = 14,
        CertificateVerify = 15,
        ClientKeyExchange = 16,
        Finished = 20
    };
};
#pragma pack(pop)

#define TLS_EXTENSION_SERVER_NAME 0x0000
#define TLS_SERVER_NAME_TYPE_HOSTNAME 0x00
