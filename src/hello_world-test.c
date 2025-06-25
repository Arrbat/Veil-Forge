#include <windows.h>
#include <stdio.h>

HWND hButton;

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch(msg)
    {
        case WM_CREATE:
            hButton = CreateWindowA(
                "BUTTON", "Click me",
                WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
                10, 40, 100, 30,
                hwnd, (HMENU)1001, NULL, NULL);
            break;

        case WM_COMMAND:
            if (LOWORD(wParam) == 1001)
            {
                MessageBoxA(hwnd, "Hello World!", "Info", MB_OK | MB_ICONINFORMATION);
            }
            break;

        case WM_SIZE:
        {
            char buf[64];
            sprintf(buf, "Width: %d, Height: %d", LOWORD(lParam), HIWORD(lParam));
            SetWindowTextA(hwnd, buf);
            break;
        }

        case WM_CLOSE:
            DestroyWindow(hwnd);
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow)
{
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "HelloWorldClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);

    if (!RegisterClass(&wc))
        return 1;

    HWND hwnd = CreateWindowEx(
        0, wc.lpszClassName, "Hello, Hello World",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        300, 200, NULL, NULL, hInstance, NULL);

    if (!hwnd) return 1;

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
