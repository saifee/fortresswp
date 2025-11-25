(function($){

    function updateScanUI(data) {
        if (!data || !data.success) return;

        var st = data.data || data; // wp_send_json_success wraps in data

        if (!st.running && !st.done) {
            $('#fw-scan-count').text('No active scan.');
            $('#fw-scan-current').text('');
            $('#fw-scan-time').text('');
            $('#fw-scan-progress-fill').css('width','0%');
            return;
        }

        var total     = st.total || 0;
        var processed = st.processed || 0;
        var percent   = st.percent || 0;
        var elapsed   = st.elapsed || 0;
        var remaining = st.remaining;

        $('#fw-scan-count').text(processed + ' / ' + total + ' files');
        $('#fw-scan-current').text(st.current_file || '');
        $('#fw-scan-progress-fill').css('width', percent + '%');

        var timeText = 'Elapsed: ' + elapsed + 's';
        if (remaining !== null && remaining !== undefined) {
            timeText += ' | ETA: ' + remaining + 's';
        }
        $('#fw-scan-time').text(timeText);
    }

    function pollScanStatus() {
        if (!$('#fw-scan-progress-wrapper').length) return; // only on scan page

        $.post(fortresswp_admin.ajax_url, {
            action: 'fortresswp_scan_status'
        }).done(function(resp){
            updateScanUI(resp);
            if (resp && resp.success && resp.data && !resp.data.done) {
                setTimeout(pollScanStatus, 2000);
            }
        });
    }

    $(document).ready(function(){

        // Scan button (Scan tab)
        $('#fw-run-scan').on('click', function(e){
            e.preventDefault();
            var $btn = $(this);
            $btn.prop('disabled', true).text('Scan Queued...');
            var fd = new FormData();
            fd.append('action','fortresswp_start_scan');
            fd.append('nonce', fortresswp_admin.scan_nonce);

            fetch(fortresswp_admin.ajax_url, {
                method: 'POST',
                body: fd,
                credentials: 'same-origin'
            }).then(r => r.json())
            .then(function(j){
                $('#fw-msg').text(JSON.stringify(j, null, 2));
                $btn.prop('disabled', false).text('Start Scan');
                pollScanStatus(); // start polling
            });
        });

        // Signature update
        $('#fw-update-sigs').on('click', function(e){
            e.preventDefault();
            fetch(fortresswp_admin.ajax_url + '?action=fortresswp_update_signatures_sync', {
                method: 'POST',
                credentials: 'same-origin'
            })
            .then(r => r.json())
            .then(j => {
                $('#fw-msg').text(JSON.stringify(j, null, 2));
            });
        });

        // Blocklist update
        $('#fw-update-blk').on('click', function(e){
            e.preventDefault();
            fetch(fortresswp_admin.ajax_url + '?action=fortresswp_update_blocklist_sync', {
                method: 'POST',
                credentials: 'same-origin'
            })
            .then(r => r.json())
            .then(j => {
                $('#fw-msg').text(JSON.stringify(j, null, 2));
            });
        });

        // TOTP verify form (still works as before)
        $('#fw-verify-form').on('submit', function(e){
            e.preventDefault();
            var code = $('#fw-totp-code').val();
            var fd = new FormData();
            fd.append('action','fortresswp_verify_totp');
            fd.append('code', code);
            fd.append('nonce', fortresswp_admin.totp_nonce);

            fetch(fortresswp_admin.ajax_url, {
                method:'POST',
                body: fd,
                credentials:'same-origin'
            })
            .then(r=>r.json())
            .then(j=>{
                $('#fw-verify-result').text(JSON.stringify(j,null,2));
            });
        });

        // Initial poll (in case scan is already running)
        pollScanStatus();
    });

})(jQuery);
