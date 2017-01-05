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
        socket.emit("send_connections_list");
    }

    socket.on('connect', function () {
        fetchConnections();
    });

    socket.on("connections_list", function (json) {
        entries.splice(0, entries.length);
        json.forEach(entry => {
            entries.push(entry);
        });
    });


    const vueApp = new Vue({
        el: "#app",
        data: {
            entries: entries,
            autoReload: true
        },
        methods: {
            refresh: fetchConnections,
            trigger_deauth_attack: (idx) => {
                console.log(idx);
            }
        }
    });

    setInterval(() => {
        if (vueApp.autoReload) {
            fetchConnections();
        }
    }, 5000);
});
