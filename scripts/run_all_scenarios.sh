#!/bin/bash
set -e

# Start background iperf3 server on gateway2
docker exec -d ipsec-gw2 iperf3 -s 2>/dev/null || true

reconfigure_and_capture() {
    SCENARIO_NAME=$1
    IKE_PROPOSAL=$2
    ESP_PROPOSAL=$3
    MODE=$4
    SESSIONS=5

    echo "=========================================================="
    echo "[*] RUNNING SCENARIO: ${SCENARIO_NAME}"
    echo "    IKE : ${IKE_PROPOSAL}"
    echo "    ESP : ${ESP_PROPOSAL}"
    echo "    MODE: ${MODE}"
    echo "=========================================================="

    # 1. Update host-side gateway1 config
    cat << CONF > gateway1/swanctl.conf
connections {
    gw1-to-gw2 {
        local_addrs  = 192.168.100.10
        remote_addrs = 192.168.100.20
        proposals    = ${IKE_PROPOSAL}

        local {
            auth = psk
            id   = gw1@lab.local
        }
        remote {
            auth = psk
            id   = gw2@lab.local
        }
        children {
            net-to-net {
                local_ts      = 192.168.100.10/32
                remote_ts     = 192.168.100.20/32
                esp_proposals = ${ESP_PROPOSAL}
                mode          = ${MODE}
                start_action  = none
            }
        }
        version = 2
    }
}

secrets {
    ike-gw1 {
        id     = gw2@lab.local
        secret = "VpnLabKey2026Secure!"
    }
}
CONF

    # 2. Update host-side gateway2 config
    cat << CONF > gateway2/swanctl.conf
connections {
    gw2-to-gw1 {
        local_addrs  = 192.168.100.20
        remote_addrs = 192.168.100.10
        proposals    = ${IKE_PROPOSAL}

        local {
            auth = psk
            id   = gw2@lab.local
        }
        remote {
            auth = psk
            id   = gw1@lab.local
        }
        children {
            net-to-net {
                local_ts      = 192.168.100.20/32
                remote_ts     = 192.168.100.10/32
                esp_proposals = ${ESP_PROPOSAL}
                mode          = ${MODE}
            }
        }
        version = 2
    }
}

secrets {
    ike-gw2 {
        id     = gw1@lab.local
        secret = "VpnLabKey2026Secure!"
    }
}
CONF

    for i in $(seq 1 $SESSIONS); do
        PCAP_FILE="/captures/${SCENARIO_NAME}_s${i}.pcap"
        echo "[+] Capturing session $i -> ${PCAP_FILE}"

        # Clean slate
        docker exec ipsec-gw1 swanctl --terminate --ike gw1-to-gw2 2>/dev/null || true
        docker exec ipsec-gw1 swanctl --load-all >/dev/null
        docker exec ipsec-gw2 swanctl --load-all >/dev/null
        sleep 1

        # Start capture
        docker exec -d ipsec-gw1 tcpdump -i eth0 -w "${PCAP_FILE}"
        sleep 1

        # Initiate tunnel
        docker exec ipsec-gw1 swanctl --initiate --child net-to-net || true

        # Generate realistic traffic: Ping burst + iperf3 TCP/UDP payloads (~2,400 packets per session)
        docker exec ipsec-gw1 ping -c 50 -i 0.02 192.168.100.20 >/dev/null || true
        docker exec ipsec-gw1 iperf3 -c 192.168.100.20 -t 2 -b 10M >/dev/null 2>&1 || true
        docker exec ipsec-gw1 iperf3 -c 192.168.100.20 -u -t 2 -b 5M >/dev/null 2>&1 || true

        # Stop capture
        docker exec ipsec-gw1 pkill tcpdump || true
        sleep 1
    done
}

# Clean old captures
rm -f captures/*.pcap

# Scenario A1: Compliant AEAD (AES-128-GCM, DH19/MODP2048)
reconfigure_and_capture "scenario_A1" "aes128-sha256-modp2048" "aes128gcm16-modp2048,aes128-sha256" "tunnel"

# Scenario A2: Compliant AEAD (AES-256-GCM, DH14)
reconfigure_and_capture "scenario_A2" "aes256-sha256-modp2048" "aes256gcm16-modp2048,aes256-sha256" "tunnel"

# Scenario B1: Legacy Transport Mode (AES-128-CBC)
reconfigure_and_capture "scenario_B1" "aes128-sha256-modp2048" "aes128-sha256" "transport"

# Scenario B2: Legacy Tunnel Mode (AES-CBC + SHA1)
reconfigure_and_capture "scenario_B2" "aes128-sha1-modp2048" "aes128-sha1" "tunnel"

# Scenario C: Plaintext ESP_NULL
reconfigure_and_capture "scenario_C" "aes128-sha256-modp2048" "null-sha256" "tunnel"

# Scenario D: Legacy Vulnerable (3DES + MD5 + MODP1024/DH2)
reconfigure_and_capture "scenario_D" "3des-md5-modp1024,aes128-sha256-modp2048" "3des-md5,aes128-sha256" "tunnel"

echo "=========================================================="
echo "[*] All 6 Scenarios Captured (30 Sessions Complete)!"
echo "=========================================================="
ls -lh captures/*.pcap
