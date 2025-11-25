(function(){

    // Run Malware Scan
    const scanBtn = document.getElementById('fw-run-scan');
    if (scanBtn) {
        scanBtn.addEventListener('click', function(){

            const fd = new FormData();
            fd.append('action', 'fortresswp_start_scan');
            fd.append('nonce', fortresswp_admin.scan_nonce);

            fetch(fortresswp_admin.ajax_url, {
                method: 'POST',
                body: fd,
                credentials: 'same-origin'
            })
            .then(r => r.json())
            .then(j => {
                document.getElementById('fw-msg').innerText =
                    JSON.stringify(j, null, 2);
            });
        });
    }

    // Update Signatures
    const sigBtn = document.getElementById('fw-update-sigs');
    if (sigBtn) {
        sigBtn.addEventListener('click', function(){

            fetch(fortresswp_admin.ajax_url + '?action=fortresswp_update_signatures_sync', {
                method: 'POST'
            })
            .then(r => r.json())
            .then(j => {
                document.getElementById('fw-msg').innerText =
                    JSON.stringify(j, null, 2);
            });
        });
    }

    // Update Blocklist
    const blkBtn = document.getElementById('fw-update-blk');
    if (blkBtn) {
        blkBtn.addEventListener('click', function(){

            fetch(fortresswp_admin.ajax_url + '?action=fortresswp_update_blocklist_sync', {
                method: 'POST'
            })
            .then(r => r.json())
            .then(j => {
                document.getElementById('fw-msg').innerText =
                    JSON.stringify(j, null, 2);
            });
        });
    }

})();
