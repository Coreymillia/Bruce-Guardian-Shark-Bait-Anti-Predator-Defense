#ifndef WIFI_DEFENSE_H
#define WIFI_DEFENSE_H

#include <Arduino.h>
#include <vector>
#include <set>

// Pure Defense WiFi Security System
// NO OFFENSIVE CAPABILITIES - DEFENSE ONLY

enum ThreatType {
    THREAT_EVIL_PORTAL,
    THREAT_KARMA_ATTACK,
    THREAT_DEAUTH_FLOOD, 
    THREAT_BEACON_SPAM,
    THREAT_PROBE_FLOOD,
    THREAT_CAPTIVE_PORTAL,
    THREAT_ROGUE_AP,
    THREAT_UNKNOWN
};

enum DefenseAction {
    DEFENSE_MONITOR,      // Passive monitoring only
    DEFENSE_ALERT,        // Alert user to threat
    DEFENSE_ISOLATE,      // Isolate device from threat
    DEFENSE_COUNTER,      // Active defense measures
    DEFENSE_REPORT        // Log and report threat
};

struct ThreatDetection {
    uint8_t sourceMac[6];
    ThreatType type;
    float confidenceLevel;
    unsigned long detectedAt;
    String description;
    DefenseAction recommendedAction;
    bool isActive;
};

struct DefenseStats {
    uint32_t threatsDetected;
    uint32_t threatsBlocked;
    uint32_t activeMonitorTime;
    uint32_t networksScanned;
    unsigned long lastUpdate;
};

// Core defense functions
void initDefenseSystem();
void startThreatMonitoring();
void stopThreatMonitoring(); 
void analyzeNetworkTraffic();
void detectRogueAccessPoints();
void monitorCaptivePortals();
void checkForEvilTwins();
void assessKarmaThreats();
void generateThreatReport();

// Defense responses (NO ATTACKS)
void alertUser(ThreatDetection threat);
void isolateFromThreat(uint8_t* threatMac);
void logThreatIncident(ThreatDetection threat);
void recommendUserAction(ThreatDetection threat);

// Monitoring functions
bool isNetworkSuspicious(wifi_ap_record_t* ap);
float calculateThreatScore(uint8_t* mac);
void updateDefenseDatabase();

// UI functions for defense menu
void displayDefenseStatus();
void showThreatHistory();
void configureDefenseSettings();

extern std::vector<ThreatDetection> activeThreatsList;
extern DefenseStats defenseStats;
extern bool defenseSystemActive;

#endif // WIFI_DEFENSE_H