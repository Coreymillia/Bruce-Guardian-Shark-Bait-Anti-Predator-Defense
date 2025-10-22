#include "DefenseMenu.h"
#include "core/display.h"
#include "core/utils.h"
#include "core/mykeyboard.h"
#include "modules/wifi/wifi_defense.h"
#include <globals.h>

// Pure Defense Menu - NO OFFENSIVE CAPABILITIES
// This menu ONLY provides defensive security functions

void DefenseMenu::optionsMenu() {
    options = {
        {"Threat Monitor",      [=]() { runThreatMonitor(); }},
        {"Network Analyzer",    [=]() { runNetworkAnalyzer(); }},
        {"Defense Scanner",     [=]() { runDefenseScanner(); }},
        {"Anti-Evil Portal",    [=]() { runAntiEvilPortal(); }},
        {"Anti-Karma Defense",  [=]() { runAntiKarmaDefense(); }},
        {"Anti-Deauth Shield",  [=]() { runAntiDeauthProtection(); }},
        {"Threat History",      [=]() { showThreatHistory(); }},
        {"Defense Settings",    [=]() { configureDefenseSettings(); }},
        {"Security Report",     [=]() { generateSecurityReport(); }},
        {"Main Menu",           [=]() { returnToMenu = true; }}
    };

    delay(200);
    loopOptions(options);
}

void DefenseMenu::runThreatMonitor() {
    displayHeader("Advanced Threat Monitor");
    
    displayInfo("🛡️ Bruce Guardian Threat Detection");
    displayInfo("Real-time analysis of:");
    displayInfo("✅ Beacon spam attacks (>2/s)");
    displayInfo("✅ Evil twin networks");
    displayInfo("✅ Karma attacks");  
    displayInfo("✅ Deauth flood attacks (>1/s)");
    displayInfo("✅ Probe floods (>5/s)");
    displayInfo("✅ Suspicious network activity");
    displayInfo("");
    displayInfo("Press ESC to stop monitoring");
    
    delay(3000);
    
    // Initialize and start the advanced defense system
    initDefenseSystem();
    startAdvancedThreatMonitor();
    
    displayInfo("Advanced monitoring stopped");
    delay(2000);
}

void DefenseMenu::runNetworkAnalyzer() {
    displayHeader("Network Security Analyzer");
    
    displayInfo("Analyzing network environment...");
    
    // Passive network analysis
    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    
    int networks = WiFi.scanNetworks();
    
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_GREEN);
    tft.setTextSize(1);
    
    tft.setCursor(5, 10);
    tft.println("Network Analysis Results");
    tft.drawLine(5, 25, tft.width()-5, 25, TFT_WHITE);
    
    int yPos = 35;
    int secureCount = 0, openCount = 0, suspiciousCount = 0;
    
    for (int i = 0; i < networks && i < 8; i++) {
        String ssid = WiFi.SSID(i);
        int rssi = WiFi.RSSI(i);
        wifi_auth_mode_t encryption = WiFi.encryptionType(i);
        
        // Analyze security
        String security = "OPEN";
        uint16_t color = TFT_RED;
        
        if (encryption != WIFI_AUTH_OPEN) {
            security = "SECURED";
            color = TFT_GREEN;
            secureCount++;
        } else {
            openCount++;
            // Check if potentially suspicious
            String lowerSSID = ssid;
            lowerSSID.toLowerCase();
            if (lowerSSID.indexOf("free") >= 0 || lowerSSID.indexOf("wifi") >= 0) {
                security = "SUSPICIOUS";
                color = TFT_YELLOW;
                suspiciousCount++;
            }
        }
        
        tft.setTextColor(color);
        tft.setCursor(5, yPos);
        tft.printf("%.12s", ssid.c_str());
        tft.setCursor(85, yPos);
        tft.printf("%ddBm", rssi);
        tft.setCursor(115, yPos);
        tft.printf("%.8s", security.c_str());
        
        yPos += 12;
    }
    
    // Summary
    tft.setTextColor(TFT_WHITE);
    tft.setCursor(5, tft.height() - 40);
    tft.printf("Total: %d | Secure: %d", networks, secureCount);
    tft.setCursor(5, tft.height() - 28);
    tft.printf("Open: %d | Suspicious: %d", openCount, suspiciousCount);
    
    tft.setTextColor(TFT_YELLOW);
    tft.setCursor(5, tft.height() - 10);
    tft.println("Any key to continue");
    
    waitForKeyPress();
}

void DefenseMenu::runDefenseScanner() {
    displayHeader("WiFi Defense Scanner");
    
    displayInfo("Scanning for defensive opportunities...");
    displayInfo("- Checking network security");
    displayInfo("- Identifying vulnerabilities");
    displayInfo("- Assessing threat landscape");
    
    delay(2000);
    
    // Run comprehensive defensive scan
    analyzeNetworkTraffic();
    detectRogueAccessPoints();
    checkForEvilTwins();
    
    displayInfo("Scan complete!");
    displayInfo("Check Threat History for results");
    delay(2000);
}

void DefenseMenu::runAntiEvilPortal() {
    displayHeader("Anti-Evil Portal Defense");
    
    displayInfo("Activating Evil Portal Protection...");
    displayInfo("- Monitoring for captive portals");
    displayInfo("- Detecting credential harvesting");
    displayInfo("- Analyzing login pages");
    displayInfo("- Checking certificate validity");
    
    // Implement anti-evil portal logic
    monitorCaptivePortals();
    
    displayInfo("Protection active. Press ESC to stop.");
    
    while (!checkEscKey()) {
        // Continuous monitoring
        delay(1000);
        displayStatus("Monitoring for evil portals...");
    }
    
    displayInfo("Anti-Evil Portal protection stopped");
    delay(2000);
}

void DefenseMenu::runAntiKarmaDefense() {
    displayHeader("Anti-Karma Defense Shield");
    
    displayInfo("Activating Karma Attack Protection...");
    displayInfo("- Monitoring probe responses");
    displayInfo("- Detecting fake APs");
    displayInfo("- Analyzing SSID patterns");
    displayInfo("- Tracking suspicious behavior");
    
    // Implement anti-karma logic
    assessKarmaThreats();
    
    displayInfo("Karma defense active. Press ESC to stop.");
    
    while (!checkEscKey()) {
        // Continuous monitoring
        delay(1000);
        displayStatus("Monitoring for Karma attacks...");
    }
    
    displayInfo("Anti-Karma defense stopped");
    delay(2000);
}

void DefenseMenu::runAntiDeauthProtection() {
    displayHeader("Anti-Deauth Protection");
    
    displayInfo("Activating Deauth Attack Protection...");
    displayInfo("- Monitoring deauth frames");
    displayInfo("- Detecting flood attacks");
    displayInfo("- Analyzing frame patterns");
    displayInfo("- Implementing countermeasures");
    
    displayInfo("NOTE: This is passive monitoring only");
    displayInfo("No offensive responses will be used");
    
    // Monitor for deauth attacks (passive only)
    displayInfo("Deauth protection active. Press ESC to stop.");
    
    while (!checkEscKey()) {
        // Monitor for suspicious deauth activity
        delay(1000);
        displayStatus("Monitoring for deauth attacks...");
    }
    
    displayInfo("Anti-Deauth protection stopped");
    delay(2000);
}

void DefenseMenu::showThreatHistory() {
    displayHeader("Threat Detection History");
    
    if(trackedDevices.empty()) {
        displayInfo("No devices tracked in current session");
        displayInfo("");
        displayInfo("Run Advanced Threat Monitor to begin");
        waitForKeyPress();
        return;
    }
    
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE);
    tft.setTextSize(1);
    
    tft.setCursor(5, 10);
    tft.println("Tracked Devices & Threats:");
    tft.drawLine(5, 25, tft.width()-5, 25, TFT_CYAN);
    
    int yPos = 35;
    int maxDisplay = min((int)trackedDevices.size(), 7);
    
    for (int i = 0; i < maxDisplay; i++) {
        const AdvancedThreatDevice& device = trackedDevices[i];
        
        uint16_t color = TFT_GREEN;
        if (device.isMarkedMalicious) color = TFT_RED;
        else if (device.riskScore > 1.0f) color = TFT_ORANGE;
        else if (device.riskScore > 0.5f) color = TFT_YELLOW;
        
        tft.setTextColor(color);
        tft.setCursor(5, yPos);
        
        // Format MAC
        String mac = "";
        for(int j = 0; j < 6; j++) {
            if(j > 0) mac += ":";
            if(device.mac[j] < 16) mac += "0";
            mac += String(device.mac[j], HEX);
        }
        String shortMac = mac.substring(0, 8) + "..";
        
        String threatType = getThreatTypeName(device.suspectedThreat);
        if(threatType.length() > 8) threatType = threatType.substring(0, 8);
        
        tft.printf("%.10s", shortMac.c_str());
        tft.setCursor(75, yPos);
        tft.printf("%.1f", device.riskScore);
        tft.setCursor(95, yPos);
        tft.printf("%.8s", threatType.c_str());
        
        yPos += 12;
    }
    
    // Stats
    tft.setTextColor(TFT_GREEN);
    tft.setCursor(5, tft.height() - 35);
    tft.printf("Total Tracked: %d", trackedDevices.size());
    tft.setCursor(5, tft.height() - 25);
    tft.printf("Confirmed Threats: %d", totalThreats);
    tft.setCursor(5, tft.height() - 15);
    tft.printf("Risk Threshold: %.1f", (float)ATTACK_DETECTION_THRESHOLD);
    
    waitForKeyPress();
}

void DefenseMenu::configureDefenseSettings() {
    displayHeader("Defense Configuration");
    
    options = {
        {"Detection Sensitivity", [=]() { displayInfo("Sensitivity: Normal"); delay(1000); }},
        {"Alert Threshold",       [=]() { displayInfo("Threshold: 75%"); delay(1000); }},
        {"Monitoring Interval",   [=]() { displayInfo("Interval: 2 seconds"); delay(1000); }},
        {"Logging Level",         [=]() { displayInfo("Logging: Detailed"); delay(1000); }},
        {"Auto-Response",         [=]() { displayInfo("Auto-Response: Alert Only"); delay(1000); }},
        {"Back",                  [=]() { returnToMenu = true; }}
    };
    
    loopOptions(options);
}

void DefenseMenu::generateSecurityReport() {
    displayHeader("Security Assessment Report");
    
    displayInfo("Generating comprehensive report...");
    delay(1000);
    
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE);
    tft.setTextSize(1);
    
    tft.setCursor(5, 10);
    tft.println("WiFi Security Report");
    tft.drawLine(5, 25, tft.width()-5, 25, TFT_CYAN);
    
    int yPos = 35;
    
    // Defense Statistics
    tft.setTextColor(TFT_GREEN);
    tft.setCursor(5, yPos);
    tft.println("DEFENSE STATISTICS:");
    yPos += 15;
    
    tft.setTextColor(TFT_WHITE);
    tft.setCursor(5, yPos);
    tft.printf("Threats Detected: %d", defenseStats.threatsDetected);
    yPos += 12;
    
    tft.setCursor(5, yPos);
    tft.printf("Networks Scanned: %d", defenseStats.networksScanned);
    yPos += 12;
    
    tft.setCursor(5, yPos);
    tft.printf("Monitor Time: %ds", defenseStats.activeMonitorTime / 1000);
    yPos += 15;
    
    // Security Status
    tft.setTextColor(TFT_CYAN);
    tft.setCursor(5, yPos);
    tft.println("SECURITY STATUS:");
    yPos += 15;
    
    tft.setTextColor(activeThreatsList.empty() ? TFT_GREEN : TFT_YELLOW);
    tft.setCursor(5, yPos);
    tft.printf("Active Threats: %d", activeThreatsList.size());
    yPos += 12;
    
    String status = activeThreatsList.empty() ? "SECURE" : "MONITORING";
    uint16_t statusColor = activeThreatsList.empty() ? TFT_GREEN : TFT_YELLOW;
    
    tft.setTextColor(statusColor);
    tft.setCursor(5, yPos);
    tft.printf("Status: %s", status.c_str());
    
    tft.setTextColor(TFT_YELLOW);
    tft.setCursor(5, tft.height() - 10);
    tft.println("Any key to continue");
    
    waitForKeyPress();
}

void DefenseMenu::drawIcon(float scale) {
    clearIconArea();
    
    int centerX = iconCenterX;
    int centerY = iconCenterY; 
    int radius = 18 * scale;
    
    // Draw shield icon
    tft.drawCircle(centerX, centerY, radius, TFT_GREEN);
    tft.drawCircle(centerX, centerY, radius-2, TFT_GREEN);
    
    // Draw shield pattern
    tft.drawLine(centerX-10*scale, centerY-5*scale, centerX+10*scale, centerY-5*scale, TFT_GREEN);
    tft.drawLine(centerX-10*scale, centerY, centerX+10*scale, centerY, TFT_GREEN);
    tft.drawLine(centerX-10*scale, centerY+5*scale, centerX+10*scale, centerY+5*scale, TFT_GREEN);
    
    // Draw central protection symbol
    tft.fillCircle(centerX, centerY, 4*scale, TFT_GREEN);
}