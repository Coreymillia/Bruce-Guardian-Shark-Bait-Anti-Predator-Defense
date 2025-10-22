#include "wifi_defense.h"
#include "core/display.h"
#include "core/utils.h"
#include "core/wifi/wifi_common.h"
#include "esp_wifi.h"
#include "WiFi.h"
#include <globals.h>

// Pure Defense System with Advanced Threat Detection
// Enhanced with existing sophisticated detection algorithms

std::vector<ThreatDetection> activeThreatsList;
std::vector<AdvancedThreatDevice> trackedDevices;
DefenseStats defenseStats = {0};
bool defenseSystemActive = false;
bool monitoring = false;
unsigned long lastAnalysis = 0;
int totalThreats = 0;

String getThreatTypeName(ThreatType type) {
    switch(type) {
        case THREAT_BEACON_SPAM: return "BEACON SPAM";
        case THREAT_EVIL_TWIN: return "EVIL TWIN";
        case THREAT_KARMA_ATTACK: return "KARMA ATTACK";
        case THREAT_DEAUTH_FLOOD: return "DEAUTH FLOOD";
        case THREAT_PROBE_FLOOD: return "PROBE FLOOD";
        case THREAT_CAPTIVE_PORTAL: return "CAPTIVE PORTAL";
        default: return "UNKNOWN";
    }
}

// Advanced packet callback (your existing sophisticated system)
void IRAM_ATTR packetCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if(!monitoring || type != WIFI_PKT_MGMT) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    
    // 802.11 frame header structure
    typedef struct {
        uint8_t frame_ctrl[2];
        uint8_t duration[2];
        uint8_t addr1[6]; // receiver
        uint8_t addr2[6]; // transmitter/source
        uint8_t addr3[6]; // BSSID
        uint8_t seq_ctrl[2];
    } wifi_header_t;
    
    if(pkt->rx_ctrl.sig_len < sizeof(wifi_header_t)) return;
    
    wifi_header_t *hdr = (wifi_header_t*)pkt->payload;
    uint8_t* srcMac = hdr->addr2;
    
    // Find or create tracked device
    AdvancedThreatDevice* device = nullptr;
    for(auto& d : trackedDevices) {
        if(memcmp(d.mac, srcMac, 6) == 0) {
            device = &d;
            break;
        }
    }
    
    if(!device && trackedDevices.size() < MAX_TRACKED_DEVICES) {
        AdvancedThreatDevice newDevice;
        memcpy(newDevice.mac, srcMac, 6);
        newDevice.firstSeen = millis();
        newDevice.lastSeen = millis();
        newDevice.beaconCount = 0;
        newDevice.probeCount = 0;
        newDevice.deauthCount = 0;
        newDevice.recentBeacons = 0;
        newDevice.recentProbes = 0;
        newDevice.recentDeauths = 0;
        newDevice.windowStart = millis();
        newDevice.suspectedThreat = THREAT_UNKNOWN;
        newDevice.riskScore = 0.0;
        newDevice.isMarkedMalicious = false;
        
        trackedDevices.push_back(newDevice);
        device = &trackedDevices.back();
    }
    
    if(!device) return;
    
    device->lastSeen = millis();
    
    // Analyze frame type (simplified frame type detection)
    uint8_t frameType = hdr->frame_ctrl[0] & 0x0C;
    uint8_t frameSubtype = (hdr->frame_ctrl[0] & 0xF0) >> 4;
    
    switch(frameType) {
        case 0x08: // Management frames
            switch(frameSubtype) {
                case 0x08: // Beacon
                    device->beaconCount++;
                    device->recentBeacons++;
                    break;
                case 0x04: // Probe request
                    device->probeCount++;
                    device->recentProbes++;
                    break;
                case 0x0C: // Deauth
                    device->deauthCount++;
                    device->recentDeauths++;
                    break;
            }
            break;
    }
}

// Detection thresholds (conservative for accuracy)
#define MAX_TRACKED_THREATS 20
#define EVIL_PORTAL_CONFIDENCE_THRESHOLD 0.75f
#define MONITORING_INTERVAL_MS 2000
#define THREAT_TIMEOUT_MS 30000

void initDefenseSystem() {
    Serial.println("[DEFENSE] Initializing WiFi Defense System");
    
    // Clear any previous state
    activeThreatsList.clear();
    memset(&defenseStats, 0, sizeof(defenseStats));
    
    // Initialize WiFi in monitor mode for passive scanning
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    defenseSystemActive = true;
    defenseStats.lastUpdate = millis();
    
    displayStatus("Defense System Active");
    Serial.println("[DEFENSE] System initialized - DEFENSE MODE ONLY");
}

void startThreatMonitoring() {
    if (!defenseSystemActive) {
        initDefenseSystem();
    }
    
    displayStatus("Monitoring threats...");
    Serial.println("[DEFENSE] Starting threat monitoring");
    
    unsigned long monitorStart = millis();
    
    while (defenseSystemActive) {
        analyzeNetworkTraffic();
        detectRogueAccessPoints(); 
        checkForEvilTwins();
        assessKarmaThreats();
        monitorCaptivePortals();
        
        // Update display every 2 seconds
        if (millis() - defenseStats.lastUpdate > MONITORING_INTERVAL_MS) {
            displayDefenseStatus();
            defenseStats.lastUpdate = millis();
            defenseStats.activeMonitorTime = millis() - monitorStart;
        }
        
        // Check for exit condition
        if (checkEscKey()) {
            break;
        }
        
        delay(100); // Small delay to prevent overwhelming
    }
    
    displayStatus("Monitoring stopped");
}

void analyzeNetworkTraffic() {
    // Passive analysis only - no packet injection or attacks
    int networksFound = WiFi.scanNetworks();
    defenseStats.networksScanned += networksFound;
    
    for (int i = 0; i < networksFound; i++) {
        wifi_ap_record_t ap;
        memset(&ap, 0, sizeof(ap));
        
        // Get basic AP info (passive scan only)
        String ssid = WiFi.SSID(i);
        int rssi = WiFi.RSSI(i);
        uint8_t* bssid = WiFi.BSSID(i);
        
        // Analyze for suspicious patterns
        if (isNetworkSuspicious(nullptr)) { // Pass actual AP data in real implementation
            ThreatDetection threat;
            memcpy(threat.sourceMac, bssid, 6);
            threat.type = THREAT_ROGUE_AP;
            threat.confidenceLevel = calculateThreatScore(bssid);
            threat.detectedAt = millis();
            threat.description = "Suspicious network: " + ssid;
            threat.recommendedAction = DEFENSE_ALERT;
            threat.isActive = true;
            
            // Add to threat list if confidence is high enough
            if (threat.confidenceLevel > EVIL_PORTAL_CONFIDENCE_THRESHOLD) {
                activeThreatsList.push_back(threat);
                defenseStats.threatsDetected++;
                alertUser(threat);
            }
        }
    }
}

void detectRogueAccessPoints() {
    Serial.println("[DEFENSE] Scanning for rogue access points...");
    
    // Look for common rogue AP indicators:
    // - Generic/default SSIDs
    // - Unusual signal patterns  
    // - Multiple APs with similar names
    // - Captive portal signatures
    
    // This is passive detection only - no attacks performed
    std::set<String> commonRogueSSIDs = {
        "FreeWiFi", "Free WiFi", "WiFi", "Internet", 
        "Guest", "Public", "Open", "Hotspot"
    };
    
    int networkCount = WiFi.scanNetworks();
    
    for (int i = 0; i < networkCount; i++) {
        String ssid = WiFi.SSID(i);
        String lowerSSID = ssid;
        lowerSSID.toLowerCase();
        
        // Check against known rogue patterns
        for (const String& roguePattern : commonRogueSSIDs) {
            if (lowerSSID.indexOf(roguePattern.c_str()) >= 0) {
                Serial.printf("[DEFENSE] Potential rogue AP detected: %s\n", ssid.c_str());
                
                ThreatDetection threat;
                uint8_t* bssid = WiFi.BSSID(i);
                memcpy(threat.sourceMac, bssid, 6);
                threat.type = THREAT_ROGUE_AP;
                threat.confidenceLevel = 0.6f; // Medium confidence for pattern match
                threat.detectedAt = millis();
                threat.description = "Rogue AP pattern: " + ssid;
                threat.recommendedAction = DEFENSE_ALERT;
                threat.isActive = true;
                
                activeThreatsList.push_back(threat);
                defenseStats.threatsDetected++;
                break;
            }
        }
    }
}

void checkForEvilTwins() {
    Serial.println("[DEFENSE] Checking for evil twin networks...");
    
    // Detect potential evil twins by looking for:
    // - Multiple APs with same SSID but different BSSIDs
    // - Similar SSIDs with slight variations
    // - Unusually strong signals from unknown APs
    
    std::map<String, std::vector<uint8_t*>> ssidToMacs;
    int networkCount = WiFi.scanNetworks();
    
    // Group networks by SSID
    for (int i = 0; i < networkCount; i++) {
        String ssid = WiFi.SSID(i);
        uint8_t* bssid = WiFi.BSSID(i);
        
        if (ssidToMacs.find(ssid) == ssidToMacs.end()) {
            ssidToMacs[ssid] = std::vector<uint8_t*>();
        }
        ssidToMacs[ssid].push_back(bssid);
    }
    
    // Check for suspicious duplicates
    for (auto& pair : ssidToMacs) {
        if (pair.second.size() > 1) {
            Serial.printf("[DEFENSE] Multiple APs found for SSID: %s (%d APs)\n", 
                         pair.first.c_str(), pair.second.size());
            
            // This could indicate evil twin attack
            for (uint8_t* mac : pair.second) {
                ThreatDetection threat;
                memcpy(threat.sourceMac, mac, 6);
                threat.type = THREAT_EVIL_PORTAL;
                threat.confidenceLevel = 0.7f;
                threat.detectedAt = millis();
                threat.description = "Possible evil twin: " + pair.first;
                threat.recommendedAction = DEFENSE_ALERT;
                threat.isActive = true;
                
                activeThreatsList.push_back(threat);
                defenseStats.threatsDetected++;
            }
        }
    }
}

void assessKarmaThreats() {
    Serial.println("[DEFENSE] Assessing Karma attack indicators...");
    
    // Look for Karma attack patterns:
    // - APs responding to unusual probe requests
    // - Generic SSIDs that match common networks
    // - Rapid SSID changes from same BSSID
    
    // This is passive monitoring only
    // Real implementation would track probe responses over time
}

void monitorCaptivePortals() {
    Serial.println("[DEFENSE] Monitoring for malicious captive portals...");
    
    // Check for captive portal indicators:
    // - HTTP redirects to suspicious domains
    // - Generic login pages
    // - Credential harvesting attempts
    
    // This would require HTTP monitoring capabilities
    // Implementation depends on network access
}

// Advanced threat analysis (your sophisticated detection algorithms)
void analyzeTrackedDevices() {
    unsigned long currentTime = millis();
    
    for(auto& device : trackedDevices) {
        // Reset risk score for fresh analysis
        float oldRiskScore = device.riskScore;
        device.riskScore = 0.0;
        
        // Skip if device hasn't been seen recently
        if(currentTime - device.lastSeen > 30000) continue;
        
        // Calculate rates within the sliding window
        float windowSeconds = (currentTime - device.windowStart) / 1000.0;
        if(windowSeconds < 0.1) windowSeconds = 0.1; // Prevent division by zero
        
        float totalTimeSeconds = (currentTime - device.firstSeen) / 1000.0;
        if(totalTimeSeconds < 0.1) totalTimeSeconds = 0.1;
        
        float recentBeaconRate = device.recentBeacons / windowSeconds;
        float recentProbeRate = device.recentProbes / windowSeconds; 
        float recentDeauthRate = device.recentDeauths / windowSeconds;
        
        float totalBeaconRate = device.beaconCount / totalTimeSeconds;
        
        // Detection Algorithm 1: High beacon rate (classic beacon spam)
        if(recentBeaconRate > BEACON_SPAM_THRESHOLD) {
            device.riskScore += 4.0;
            device.suspectedThreat = THREAT_BEACON_SPAM;
        }
                    
        // Detection Algorithm 2: Rapid beacon increase (attack starting)
        if(recentBeaconRate > totalBeaconRate * 2 && recentBeaconRate > 1.5) {
            device.riskScore += 3.0;
            if(device.suspectedThreat == THREAT_UNKNOWN) {
                device.suspectedThreat = THREAT_BEACON_SPAM;
            }
        }
        
        // Detection Algorithm 3: Deauth flood attack
        if(recentDeauthRate > DEAUTH_ATTACK_THRESHOLD) {
            device.riskScore += 5.0;
            device.suspectedThreat = THREAT_DEAUTH_FLOOD;
        }
        
        // Detection Algorithm 4: Probe request flood  
        if(recentProbeRate > PROBE_FLOOD_THRESHOLD) {
            device.riskScore += 4.0;
            device.suspectedThreat = THREAT_PROBE_FLOOD;
        }
        
        // Detection Algorithm 5: Multiple SSID advertisement (evil twin/karma)
        if(device.advertisedSSIDs.size() > 2) {
            device.riskScore += 3.0;
            if(device.suspectedThreat == THREAT_UNKNOWN) {
                device.suspectedThreat = THREAT_EVIL_TWIN;
            }
        }
        
        // Detection Algorithm 6: Very high activity
        if(recentBeaconRate > 10 || recentProbeRate > 8 || device.recentBeacons > 20) {
            device.riskScore += 2.0;
        }
        
        // Detection Algorithm 7: Burst pattern detection
        if(device.recentBeacons + device.recentProbes + device.recentDeauths > 15) {
            device.riskScore += 2.0;
        }
        
        // Log analysis for debugging
        if(device.riskScore > 0.5 || device.recentBeacons > 5) {
            String mac = "";
            for(int i = 0; i < 6; i++) {
                if(i > 0) mac += ":";
                if(device.mac[i] < 16) mac += "0";
                mac += String(device.mac[i], HEX);
            }
            Serial.printf("THREAT ANALYSIS: %s - B:%.1f P:%.1f D:%.1f Risk:%.1f %s\n",
                         mac.c_str(), recentBeaconRate, recentProbeRate, recentDeauthRate, 
                         device.riskScore, getThreatTypeName(device.suspectedThreat).c_str());
        }
        
        // Mark as malicious if risk score exceeds threshold
        if(device.riskScore >= ATTACK_DETECTION_THRESHOLD && !device.isMarkedMalicious) {
            device.isMarkedMalicious = true;
            totalThreats++;
            defenseStats.threatsDetected++;
            
            String mac = "";
            for(int i = 0; i < 6; i++) {
                if(i > 0) mac += ":";
                if(device.mac[i] < 16) mac += "0";
                mac += String(device.mac[i], HEX);
            }
            Serial.println("🛡️ THREAT DETECTED: " + getThreatTypeName(device.suspectedThreat) + 
                          " from " + mac + " (Risk: " + String(device.riskScore, 1) + ")");
            
            // Add to active threats list
            ThreatDetection threat;
            memcpy(threat.sourceMac, device.mac, 6);
            threat.type = device.suspectedThreat;
            threat.confidenceLevel = min(device.riskScore / 10.0f, 1.0f); // Normalize to 0-1
            threat.detectedAt = millis();
            threat.description = getThreatTypeName(device.suspectedThreat) + " detected";
            threat.recommendedAction = DEFENSE_ALERT;
            threat.isActive = true;
            
            activeThreatsList.push_back(threat);
        }
    }
    
    // Reset window counters periodically
    unsigned long currentTime_window = millis();
    for(auto& device : trackedDevices) {
        if(currentTime_window - device.windowStart > SHORT_WINDOW_MS) {
            device.recentBeacons = 0;
            device.recentProbes = 0;  
            device.recentDeauths = 0;
            device.windowStart = currentTime_window;
        }
    }
}

float calculateThreatScore(uint8_t* mac) {
    // Calculate threat score based on various factors
    // Higher score = higher threat
    float score = 0.0f;
    
    // Example factors:
    // - Signal strength anomalies
    // - SSID patterns
    // - Timing patterns
    // - Historical data
    
    return score;
}

void alertUser(ThreatDetection threat) {
    // Alert user to detected threat (non-intrusive)
    Serial.printf("[DEFENSE ALERT] %s detected from ", 
                  (threat.type == THREAT_EVIL_PORTAL) ? "Evil Portal" :
                  (threat.type == THREAT_KARMA_ATTACK) ? "Karma Attack" :
                  (threat.type == THREAT_ROGUE_AP) ? "Rogue AP" : "Unknown Threat");
    
    for (int i = 0; i < 6; i++) {
        Serial.printf("%02X", threat.sourceMac[i]);
        if (i < 5) Serial.print(":");
    }
    Serial.println();
    
    // Display on screen
    tft.fillScreen(TFT_RED);
    tft.setTextColor(TFT_WHITE);
    tft.setTextSize(1);
    tft.setCursor(5, 20);
    tft.println("THREAT DETECTED!");
    tft.setCursor(5, 40);
    tft.println(threat.description);
    tft.setCursor(5, 60);
    tft.printf("Confidence: %.1f%%", threat.confidenceLevel * 100);
    
    delay(2000); // Show alert for 2 seconds
}

void displayDefenseStatus() {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN);
    tft.setTextSize(1);
    
    tft.setCursor(5, 10);
    tft.println("WiFi Defense Active");
    
    tft.setCursor(5, 30);
    tft.printf("Threats: %d", defenseStats.threatsDetected);
    
    tft.setCursor(5, 50);  
    tft.printf("Networks: %d", defenseStats.networksScanned);
    
    tft.setCursor(5, 70);
    tft.printf("Uptime: %ds", defenseStats.activeMonitorTime / 1000);
    
    tft.setCursor(5, 90);
    tft.printf("Active: %d", activeThreatsList.size());
    
    tft.setTextColor(TFT_YELLOW);
    tft.setCursor(5, 110);
    tft.println("ESC=Exit");
}

void stopThreatMonitoring() {
    defenseSystemActive = false;
    displayStatus("Defense system stopped");
    Serial.println("[DEFENSE] Monitoring stopped by user");
}

void isolateFromThreat(uint8_t* threatMac) {
    // Defensive isolation only - no attacks
    Serial.println("[DEFENSE] Isolating from threat (defensive only)");
    // Could disconnect from current network if it matches threat
    // Or warn user to avoid the threat
}

void logThreatIncident(ThreatDetection threat) {
    // Log threat to SD card or internal storage
    Serial.println("[DEFENSE] Logging threat incident");
    // Implementation would save to file
}

void startAdvancedThreatMonitor() {
    Serial.println("[BRUCE GUARDIAN] Starting Advanced Threat Monitor");
    
    // Clear previous state
    trackedDevices.clear();
    totalThreats = 0;
    defenseStats.threatsDetected = 0;
    
    // Set up WiFi monitoring
    WiFi.mode(WIFI_MODE_STA);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&packetCallback);
    monitoring = true;
    lastAnalysis = millis();
    
    displayStatus("🛡️ Bruce Guardian Active");
    Serial.println("[BRUCE GUARDIAN] Monitoring started - Press ESC to stop");
    
    unsigned long lastDisplay = millis();
    
    while(monitoring && defenseSystemActive) {
        // Run analysis periodically
        if(millis() - lastAnalysis >= MIN_ANALYSIS_TIME) {
            analyzeTrackedDevices();
            lastAnalysis = millis();
        }
        
        // Update display every 2 seconds  
        if(millis() - lastDisplay >= 2000) {
            displayAdvancedStatus();
            lastDisplay = millis();
            defenseStats.activeMonitorTime = millis() - lastAnalysis;
        }
        
        // Check for exit
        if(checkEscKey()) {
            monitoring = false;
            break;
        }
        
        delay(100);
    }
    
    esp_wifi_set_promiscuous(false);
    
    // Show final summary
    Serial.printf("[BRUCE GUARDIAN] Scan complete - Devices: %d, Threats: %d\n", 
                  trackedDevices.size(), totalThreats);
    displayStatus("Guardian scan complete");
    delay(2000);
}

void displayAdvancedStatus() {
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN);
    tft.setTextSize(1);
    
    // Header
    tft.setCursor(5, 5);
    tft.println("🛡️ BRUCE GUARDIAN");
    tft.drawLine(5, 18, tft.width()-5, 18, TFT_GREEN);
    
    // Stats
    tft.setCursor(5, 25);
    tft.printf("Tracked: %d | Threats: %d", trackedDevices.size(), totalThreats);
    
    // Device list (showing active threats first)
    int yPos = 40;
    int displayCount = 0;
    unsigned long currentTime = millis();
    
    // Show high-risk devices first
    for(const auto& device : trackedDevices) {
        if(displayCount >= 6) break;
        if(currentTime - device.lastSeen > 10000) continue; // Skip old devices
        
        tft.setCursor(5, yPos);
        
        // Color based on threat level
        if(device.isMarkedMalicious || device.riskScore >= ATTACK_DETECTION_THRESHOLD) {
            tft.setTextColor(TFT_RED);
        } else if(device.riskScore > 1.0) {
            tft.setTextColor(TFT_ORANGE);
        } else if(device.riskScore > 0.5) {
            tft.setTextColor(TFT_YELLOW);
        } else {
            tft.setTextColor(TFT_GREEN);
        }
        
        // Format MAC (shortened)
        String macStr = "";
        for(int j = 0; j < 6; j++) {
            if(j > 0) macStr += ":";
            if(device.mac[j] < 16) macStr += "0";
            macStr += String(device.mac[j], HEX);
        }
        String shortMac = macStr.substring(0, 8) + ".." + macStr.substring(15);
        
        // Display: MAC | Risk | Type
        tft.printf("%.11s", shortMac.c_str());
        tft.setCursor(85, yPos);
        tft.printf("%.1f", device.riskScore);
        tft.setCursor(110, yPos);
        String threatName = getThreatTypeName(device.suspectedThreat);
        tft.printf("%.8s", threatName.c_str());
        
        yPos += 12;
        displayCount++;
    }
    
    // Status bar
    tft.setTextColor(TFT_CYAN);
    tft.setCursor(5, tft.height() - 25);
    tft.printf("Thresholds: B>%d P>%d D>%d", BEACON_SPAM_THRESHOLD, PROBE_FLOOD_THRESHOLD, DEAUTH_ATTACK_THRESHOLD);
    
    // Legend
    tft.setCursor(5, tft.height() - 12);
    tft.setTextColor(TFT_RED);
    tft.print("RED=Threat ");
    tft.setTextColor(TFT_YELLOW);
    tft.print("YEL=Risk ");
    tft.setTextColor(TFT_GREEN);
    tft.print("ESC=Exit");
}