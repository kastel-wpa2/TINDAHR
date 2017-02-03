$(() => {
    "use strict";

    const entries = [];

    const socket = io.connect('http://' + document.domain + ':' + location.port);

    function fetchConnections() {
        console.log("Request sent!");
        socket.emit("send_connections_list");
    }

    socket.on('connect', function () {
        fetchConnections();
    });

    socket.on("connections_list", function (json) {
        console.log("Retrieved new!");        
        entries.splice(0, entries.length);
        json.forEach(entry => {
            entries.push(entry);
        });
    });


    const vueApp = new Vue({
        el: "#app",
        data: {
            STEP_SETUP: 0,
            STEP_IN_PROGRESS: 1,
            STEP_DONE: 2,
            entries: entries,
            autoReload: true,
            showDeauthModal: false,
            deauthStep: null,
            deauthOptions: {},
            deauthResults: {},
            filterBy: ""
        },
        methods: {
            refresh: fetchConnections,
            openDeauthDialog: function (idx) {
                const selectedConnection = this.entries[idx];

                this.deauthOptions = {
                    deauth_packet_count: 128,
                    target_mac: selectedConnection.sa,
                    ap_mac: selectedConnection.da,
                    channel: selectedConnection.channel
                };

                this.deauthStep = this.STEP_SETUP;
                this.showDeauthModal = true;
            },
            closeDeauthDialog: function () {
                this.showDeauthModal = false;
            },
            startDeauthAttack: function () {
                this.deauthStep = this.STEP_IN_PROGRESS;

                const opts = this.deauthOptions;

                socket.emit("start_deauth", {
                    capture_handshake: true,
                    deauth_packets_amount: opts.deauth_packet_count,
                    target_mac: opts.target_mac,
                    ap_mac: opts.ap_mac,
                    channel: opts.channel
                });

                console.log("'start_deauth' event emitted!");
            },
            filter: function (idx) {
                if (this.filterBy === "") {
                    return true;
                }

                const selectedConnection = this.entries[idx];
                console.log("HERE: ", idx);
                const keys = Object.keys(selectedConnection);
                for (let key of keys) {
                    const field = selectedConnection[key];
                    if (typeof field !== "string") {
                        continue;
                    }

                    if (field.toLowerCase().indexOf(this.filterBy.toLowerCase()) > -1) {
                        return true;
                    }
                }

                return false;
            }
        }
    });

    socket.on("deauth_done", (deauthResults) => {
        console.log("Received results", deauthResults);
        vueApp.deauthResults = deauthResults;
        vueApp.deauthStep = vueApp.STEP_DONE;
    });

    setInterval(() => {
        if (vueApp.autoReload) {
            fetchConnections();
        }
    }, 5000);
});
