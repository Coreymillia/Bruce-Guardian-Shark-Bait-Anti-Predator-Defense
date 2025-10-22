#ifndef WIFI_DEFENSE_H
#define WIFI_DEFENSE_H

#include <Arduino.h>
#include <vector>
#include <set>

// Pure Defense WiFi Security System
// NO OFFENSIVE CAPABILITIES - DEFENSE ONLY

// Enhanced threat types matching your existing detection system
enum ThreatType {
    THREAT_BEACON_SPAM,
    THREAT_EVIL_TWIN, 
    THREAT_KARMA_ATTACK,
    THREAT_DEAUTH_FLOOD,
    THREAT_PROBE_FLOOD,
    THREAT_CAPTIVE_PORTAL,
    THREAT_ROGUE_AP,
    THREAT_UNKNOWN
};

// Advanced tracking structure (based on your existing TrackedDevice)
struct AdvancedThreatDevice {
    uint8_t mac[6];
    unsigned long firstSeen;
    unsigned long lastSeen;
    uint32_t beaconCount;
    uint32_t probeCount; 
    uint32_t deauthCount;
    uint32_t recentBeacons;     // beacons in last window
    uint32_t recentProbes;      // probes in last window
    uint32_t recentDeauths;     // deauths in last window
    unsigned long windowStart; // start of measurement window
    std::set<String> advertisedSSIDs;
    ThreatType suspectedThreat;
    float riskScore;
    bool isMarkedMalicious;
};

// Detection thresholds (from your tuned system)
#define MAX_TRACKED_DEVICES 50
#define BEACON_SPAM_THRESHOLD 2   // beacons/second
#define DEAUTH_ATTACK_THRESHOLD 1 // deauths/second  
#define PROBE_FLOOD_THRESHOLD 5   // probes/second
#define ATTACK_DETECTION_THRESHOLD 2 // risk score to confirm attack
#define SHORT_WINDOW_MS 3000      // 3 second sliding window
#define MIN_ANALYSIS_TIME 500     // minimum analysis interval

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

// Global state for defense system
extern std::vector<ThreatDetection> activeThreatsList;
extern std::vector<AdvancedThreatDevice> trackedDevices;
extern DefenseStats defenseStats;
extern bool defenseSystemActive;
extern bool monitoring;
extern unsigned long lastAnalysis;
extern int totalThreats;

// Advanced detection functions (your existing algorithms)
void IRAM_ATTR packetCallback(void* buf, wifi_promiscuous_pkt_type_t type);
void analyzeTrackedDevices();
String getThreatTypeName(ThreatType type);
void startAdvancedThreatMonitor();

#endif // WIFI_DEFENSE_H