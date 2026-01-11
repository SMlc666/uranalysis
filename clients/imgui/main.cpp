#include <windows.h>
#include "app/application.h"

int APIENTRY WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int) {
    client::Application app;
    if (!app.init(instance)) {
        return 1;
    }
    return app.run();
}
