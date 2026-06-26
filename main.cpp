#include <gtk/gtk.h>
#include <fstream>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/socket.h>

enum
{
    COL_IP = 0,
    COL_MAC,
    COL_HOSTNAME,
    COL_STATUS,
    NUM_COLS
};

struct DeviceInfo
{
    std::string ip;
    std::string mac;
    std::string hostname;
    bool online = false;
};

struct AppWidgets
{
    GtkWidget *window;
    GtkWidget *info_label;
    GtkWidget *tree_view;
    GtkListStore *store;
    GtkWidget *scan_button;
    GtkWidget *autorefresh_switch;
    GtkWidget *interval_spin;
    GtkWidget *statusbar;
    guint statusbar_ctx;
    guint timeout_id = 0;
    bool scanning = false;
};

static AppWidgets g_app;
static std::mutex g_table_mutex;
static std::map<std::string, DeviceInfo> g_device_table;

static bool getLocalNetwork(std::string &ifaceName, uint32_t &ipAddr, uint32_t &netmask)
{
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1)
        return false;

    bool found = false;
    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next)
    {
        if (!ifa->ifa_addr)
            continue;
        if (ifa->ifa_addr->sa_family != AF_INET)
            continue;

        std::string name = ifa->ifa_name;
        if (name == "lo")
            continue;
        if (!ifa->ifa_netmask)
            continue;

        auto *sa = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_addr);
        auto *nm = reinterpret_cast<struct sockaddr_in *>(ifa->ifa_netmask);

        ipAddr = sa->sin_addr.s_addr;
        netmask = nm->sin_addr.s_addr;
        ifaceName = name;
        found = true;
        break;
    }
    freeifaddrs(ifaddr);
    return found;
}

static std::vector<std::string> computeHostRange(uint32_t ipAddr, uint32_t netmask)
{
    std::vector<std::string> hosts;
    uint32_t network = ipAddr & netmask;
    uint32_t broadcast = network | (~netmask);

    uint32_t start = ntohl(network) + 1;
    uint32_t end = ntohl(broadcast);
    if (end > start)
        end -= 1;

    if (end - start > 1024)
        end = start + 1024;

    for (uint32_t h = start; h <= end; h++)
    {
        struct in_addr a;
        a.s_addr = htonl(h);
        hosts.push_back(inet_ntoa(a));
    }
    return hosts;
}

static bool pingHost(const std::string &ip, int timeoutSec = 1)
{
    std::ostringstream cmd;
    cmd << "ping -c 1 -W " << timeoutSec << " " << ip << " > /dev/null 2>&1";
    int ret = system(cmd.str().c_str());
    return ret == 0;
}

static std::string getMacFromArpTable(const std::string &ip)
{
    std::ifstream arp("/proc/net/arp");
    if (!arp.is_open())
        return "??:??:??:??:??:??";

    std::string line;
    std::getline(arp, line);
    while (std::getline(arp, line))
    {
        std::istringstream iss(line);
        std::string ipAddr, hwType, flags, hwAddr, mask, device;
        iss >> ipAddr >> hwType >> flags >> hwAddr >> mask >> device;
        if (ipAddr == ip && hwAddr != "00:00:00:00:00:00")
        {
            return hwAddr;
        }
    }
    return "??:??:??:??:??:??";
}

static std::string getHostname(const std::string &ip)
{
    struct sockaddr_in sa{};
    sa.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip.c_str(), &sa.sin_addr) != 1)
        return "(unknown)";

    char host[NI_MAXHOST];
    int result = getnameinfo(reinterpret_cast<struct sockaddr *>(&sa), sizeof(sa),
                             host, NI_MAXHOST, nullptr, 0, NI_NAMEREQD);
    if (result == 0)
        return std::string(host);
    return "(unknown)";
}

static void scanHostWorker(const std::string &ip)
{
    bool alive = pingHost(ip);
    std::lock_guard<std::mutex> lock(g_table_mutex);

    if (alive)
    {
        DeviceInfo info;
        info.ip = ip;
        info.mac = getMacFromArpTable(ip);
        info.hostname = getHostname(ip);
        info.online = true;
        g_device_table[ip] = info;
    }
    else
    {
        auto it = g_device_table.find(ip);
        if (it != g_device_table.end())
        {
            it->second.online = false;
        }
    }
}

static gboolean refresh_list_store(gpointer)
{
    std::lock_guard<std::mutex> lock(g_table_mutex);

    gtk_list_store_clear(g_app.store);
    int online_count = 0;

    for (auto &pair : g_device_table)
    {
        auto &d = pair.second;
        if (d.online)
            online_count++;

        GtkTreeIter iter;
        gtk_list_store_append(g_app.store, &iter);
        gtk_list_store_set(g_app.store, &iter,
                           COL_IP, d.ip.c_str(),
                           COL_MAC, d.mac.c_str(),
                           COL_HOSTNAME, d.hostname.c_str(),
                           COL_STATUS, d.online ? "online" : "offline",
                           -1);
    }

    std::ostringstream msg;
    msg << "Count: " << online_count;
    gtk_statusbar_pop(GTK_STATUSBAR(g_app.statusbar), g_app.statusbar_ctx);
    gtk_statusbar_push(GTK_STATUSBAR(g_app.statusbar), g_app.statusbar_ctx, msg.str().c_str());

    gtk_widget_set_sensitive(g_app.scan_button, TRUE);
    g_app.scanning = false;

    return G_SOURCE_REMOVE;
}

static void run_scan_thread()
{
    std::string iface;
    uint32_t ipAddr = 0, netmask = 0;

    if (!getLocalNetwork(iface, ipAddr, netmask))
    {
        g_idle_add(refresh_list_store, nullptr);
        return;
    }

    auto hosts = computeHostRange(ipAddr, netmask);
    const size_t maxConcurrent = 50;
    std::vector<std::thread> threads;
    threads.reserve(maxConcurrent);

    for (auto &h : hosts)
    {
        threads.emplace_back(scanHostWorker, h);
        if (threads.size() >= maxConcurrent)
        {
            for (auto &t : threads)
                t.join();
            threads.clear();
        }
    }
    for (auto &t : threads)
        t.join();

    g_idle_add(refresh_list_store, nullptr);
}

static void on_scan_clicked(GtkButton *, gpointer)
{
    if (g_app.scanning)
        return;
    g_app.scanning = true;
    gtk_widget_set_sensitive(g_app.scan_button, FALSE);
    gtk_statusbar_pop(GTK_STATUSBAR(g_app.statusbar), g_app.statusbar_ctx);
    gtk_statusbar_push(GTK_STATUSBAR(g_app.statusbar), g_app.statusbar_ctx, "Scanning...");

    std::thread(run_scan_thread).detach();
}

static gboolean on_autorefresh_tick(gpointer)
{
    if (!g_app.scanning)
    {
        on_scan_clicked(nullptr, nullptr);
    }
    return G_SOURCE_CONTINUE;
}

static void update_autorefresh_timer()
{
    if (g_app.timeout_id != 0)
    {
        g_source_remove(g_app.timeout_id);
        g_app.timeout_id = 0;
    }

    if (gtk_switch_get_active(GTK_SWITCH(g_app.autorefresh_switch)))
    {
        int interval = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(g_app.interval_spin));
        if (interval <= 0)
            interval = 30;
        g_app.timeout_id = g_timeout_add_seconds(interval, on_autorefresh_tick, nullptr);
    }
}

static void on_autorefresh_toggled(GtkSwitch *, gboolean, gpointer)
{
    update_autorefresh_timer();
}

static void on_interval_changed(GtkSpinButton *, gpointer)
{
    update_autorefresh_timer();
}

static void build_window()
{
    g_app.window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(g_app.window), "Network Monitor");
    gtk_window_set_default_size(GTK_WINDOW(g_app.window), 760, 480);
    gtk_container_set_border_width(GTK_CONTAINER(g_app.window), 10);
    g_signal_connect(g_app.window, "destroy", G_CALLBACK(gtk_main_quit), nullptr);

    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(g_app.window), vbox);

    g_app.info_label = gtk_label_new("Detecting local network...");
    gtk_widget_set_halign(g_app.info_label, GTK_ALIGN_START);
    gtk_box_pack_start(GTK_BOX(vbox), g_app.info_label, FALSE, FALSE, 0);

    GtkWidget *toolbar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(vbox), toolbar, FALSE, FALSE, 0);

    g_app.scan_button = gtk_button_new_with_label("Scan Now");
    g_signal_connect(g_app.scan_button, "clicked", G_CALLBACK(on_scan_clicked), nullptr);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.scan_button, FALSE, FALSE, 0);

    GtkWidget *auto_label = gtk_label_new("Auto-refresh:");
    gtk_box_pack_start(GTK_BOX(toolbar), auto_label, FALSE, FALSE, 0);

    g_app.autorefresh_switch = gtk_switch_new();
    gtk_switch_set_active(GTK_SWITCH(g_app.autorefresh_switch), TRUE);

    g_signal_connect(g_app.autorefresh_switch, "notify::active", G_CALLBACK(on_autorefresh_toggled), nullptr);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.autorefresh_switch, FALSE, FALSE, 0);

    GtkWidget *interval_label = gtk_label_new("Interval (seconds):");
    gtk_box_pack_start(GTK_BOX(toolbar), interval_label, FALSE, FALSE, 0);

    g_app.interval_spin = gtk_spin_button_new_with_range(5, 600, 5);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(g_app.interval_spin), 30);
    g_signal_connect(g_app.interval_spin, "value-changed", G_CALLBACK(on_interval_changed), nullptr);
    gtk_box_pack_start(GTK_BOX(toolbar), g_app.interval_spin, FALSE, FALSE, 0);

    GtkWidget *scrolled = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

    g_app.store = gtk_list_store_new(NUM_COLS, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    g_app.tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(g_app.store));
    gtk_container_add(GTK_CONTAINER(scrolled), g_app.tree_view);

    const char *titles[NUM_COLS] = {"IP Address", "MAC Address", "Hostname", "Status"};
    for (int i = 0; i < NUM_COLS; i++)
    {
        GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
        GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes(
            titles[i], renderer, "text", i, nullptr);
        gtk_tree_view_column_set_resizable(column, TRUE);
        gtk_tree_view_column_set_sort_column_id(column, i);
        gtk_tree_view_append_column(GTK_TREE_VIEW(g_app.tree_view), column);
    }

    g_app.statusbar = gtk_statusbar_new();
    g_app.statusbar_ctx = gtk_statusbar_get_context_id(GTK_STATUSBAR(g_app.statusbar), "main");
    gtk_box_pack_start(GTK_BOX(vbox), g_app.statusbar, FALSE, FALSE, 0);
    gtk_statusbar_push(GTK_STATUSBAR(g_app.statusbar), g_app.statusbar_ctx, "Ready. Click \"Scan Now\" to start.");
}

static void update_info_label()
{
    std::string iface;
    uint32_t ipAddr = 0, netmask = 0;

    if (getLocalNetwork(iface, ipAddr, netmask))
    {
        struct in_addr ipStruct{};
        ipStruct.s_addr = ipAddr;
        struct in_addr maskStruct{};
        maskStruct.s_addr = netmask;

        std::ostringstream text;
        text << "Interface: " << iface
             << "   IP: " << inet_ntoa(ipStruct)
             << "   Netmask: " << inet_ntoa(maskStruct);
        gtk_label_set_text(GTK_LABEL(g_app.info_label), text.str().c_str());
    }
    else
    {
        gtk_label_set_text(GTK_LABEL(g_app.info_label), "Failed to detect local network interface.");
    }
}

int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);

    build_window();
    update_info_label();

    gtk_widget_show_all(g_app.window);
    gtk_main();

    return 0;
}