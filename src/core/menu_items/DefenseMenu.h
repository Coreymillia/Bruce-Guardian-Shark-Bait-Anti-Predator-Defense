#ifndef DEFENSE_MENU_H
#define DEFENSE_MENU_H

#include "core/menu_items/MenuItemInterface.h"

class DefenseMenu : public MenuItemInterface {
public:
    void optionsMenu(void);
    void drawIcon(float scale);

private:
    void runThreatMonitor();
    void runNetworkAnalyzer(); 
    void runDefenseScanner();
    void showThreatHistory();
    void configureDefenseSettings();
    void runAntiEvilPortal();
    void runAntiKarmaDefense();
    void runAntiDeauthProtection();
    void displayDefenseStatus();
    void generateSecurityReport();
};

#endif