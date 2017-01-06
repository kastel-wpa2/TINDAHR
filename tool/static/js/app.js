$(() => {
    "use strict";

    const entries = [{
        sa: "sa",
        da: "da",
        ssid: "ssid",
        age: "age"
    }];

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
            deauthPacketNumber: "",
            _currentSelectionIdx: -1,
            deauthResults: {}
        },
        methods: {
            refresh: fetchConnections,
            openDeauthDialog: function (idx) {
                console.log(this.showDeauthModal);
                this.showDeauthModal = true;
                this.deauthStep = this.STEP_SETUP;
                this._currentSelectionIdx = idx;
                console.log(idx);
            },
            closeDeauthDialog: function () {
                this.showDeauthModal = false;
            },
            startDeauthAttack: function () {
                this.deauthStep = this.STEP_IN_PROGRESS;
                
                const selectedConnection = this.entries[this._currentSelectionIdx];
                
                socket.emit("start_deauth", {
                    capture_handshake: true,
                    deauth_packets_amount: this.deauthPacketNumber,
                    target_mac: selectedConnection.sa,
                    ap_mac: selectedConnection.da,
                    channel: selectedConnection.channel
                });

                console.log("'start_deauth' event emitted!");
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
