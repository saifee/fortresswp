(function($){

    function humanMessage(target, msg, type) {
        var $t = $(target);
        var klass = 'fw-msg-info';
        if (type === 'success') klass = 'fw-msg-success';
        if (type === 'error') klass = 'fw-msg-error';
        $t.removeClass('fw-msg-info fw-msg-success fw-msg-error')
          .addClass(klass)
          .text(msg);
    }

    function updateScanUI(resp) {
        if (!resp || !resp.success) {
            return;
        }
        var st = resp.data || {};
        if (!$('#fw-scan-progress-wrapper').length) return;

        if (!st.running && !st.done && !st.total) {
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

        $('#fw-scan-count').text(processed + ' / ' + total + ' files scanned');
        $('#fw-scan-current').text(st.current_file || '');
        $('#fw-scan-progress-fill').css('width', percent + '%');

        var timeText = 'Elapsed: ' + elapsed + ' sec';
        if (remaining !== null && remaining !== undefined) {
            timeText += ' | Estimated remaining: ' + remaining + ' sec';
        }
        $('#fw-scan-time').text(timeText);

        if (st.done) {
            humanMessage('#fw-msg', 'Scan completed. Check the Reports tab for detailed results.', 'success');
        }
    }

    function pollScanStatus() {
        if (!$('#fw-scan-progress-wrapper').length) return;

        $.post(fortresswp_admin.ajax_url, {
            action: 'fortresswp_scan_status'
        }).done(function(resp){
            updateScanUI(resp);
            if (resp && resp.success && resp.data && !resp.data.done) {
                setTimeout(pollScanStatus, 2000);
            }
        });
    }

    function applyAIProviderDefaults() {
        var provider = $('#fw-ai-provider').val();
        var $endpoint = $('#fw-ai-endpoint');

        var defaults = {
            'openai':    'https://api.openai.com/v1/chat/completions',
            'openrouter':'https://openrouter.ai/api/v1/chat/completions',
            'ollama':    'http://localhost:11434/api/chat',
            'kingslee':  'https://api.kingslee.net/fortresswp/analyze'
        };

        if (provider === 'custom') {
            $endpoint.prop('readonly', false);
            // keep whatever user typed
        } else {
            $endpoint.val(defaults[provider] || '');
            $endpoint.prop('readonly', true);
        }
    }

    $(document).ready(function(){

        // AI provider change
        $('#fw-ai-provider').on('change', function(){
            applyAIProviderDefaults();
        });

        // On load, enforce proper endpoint state
        if ($('#fw-ai-provider').length) {
            applyAIProviderDefaults();
        }

        // Stop scan
        $('#fw-stop-scan').on('click', function(e){
            e.preventDefault();
            if (!confirm('Are you sure you want to stop the scan?')) return;
            var fd = new FormData();
            fd.append('action', 'fortresswp_abort_scan');

            fetch(fortresswp_admin.ajax_url, {
                method: 'POST',
                body: fd,
                credentials: 'same-origin'
            })
            .then(r => r.json())
            .then(function(data){
                humanMessage('#fw-msg', 'Scan stopped successfully.', 'success');
                setTimeout(function(){ location.reload(); }, 1500);
            })
            .catch(function(err){
                humanMessage('#fw-msg', 'Error stopping scan: ' + err, 'error');
            });
        });

        // Start scan
        $('#fw-run-scan').on('click', function(e){
            e.preventDefault();
            var $btn = $(this);
            $btn.prop('disabled', true).text('Scanning...');
            var fd = new FormData();
            fd.append('action','fortresswp_start_scan');
            fd.append('nonce', fortresswp_admin.scan_nonce);

            fetch(fortresswp_admin.ajax_url, {
                method: 'POST',
                body: fd,
                credentials: 'same-origin'
            })
            .then(r => r.json())
            .then(function(j){
                if (j.success) {
                    humanMessage('#fw-msg', 'Scan started. You can watch the progress below and view detailed reports in the Reports tab.', 'success');
                    pollScanStatus();
                } else {
                    humanMessage('#fw-msg', 'Could not start scan: ' + (j.data || j), 'error');
                }
                $btn.prop('disabled', false).text('Start Scan');
            })
            .catch(function(err){
                humanMessage('#fw-msg', 'Scan error: ' + err, 'error');
                $btn.prop('disabled', false).text('Start Scan');
            });
        });

        // Update Signatures
        $('#fw-update-sigs').on('click', function(e){
            e.preventDefault();
            fetch(fortresswp_admin.ajax_url + '?action=fortresswp_update_signatures_sync', {
                method: 'POST',
                credentials: 'same-origin'
            })
            .then(r => r.json())
            .then(function(j){
                if (j.success) {
                    humanMessage('#fw-msg', 'Signatures updated successfully.', 'success');
                } else {
                    humanMessage('#fw-msg', 'Failed to update signatures.', 'error');
                }
            });
        });

        // Update Blocklist
        $('#fw-update-blk').on('click', function(e){
            e.preventDefault();
            fetch(fortresswp_admin.ajax_url + '?action=fortresswp_update_blocklist_sync', {
                method: 'POST',
                credentials: 'same-origin'
            })
            .then(r => r.json())
            .then(function(j){
                if (j.success) {
                    humanMessage('#fw-msg', 'Blocklist updated successfully.', 'success');
                } else {
                    humanMessage('#fw-msg', 'Failed to update blocklist.', 'error');
                }
            });
        });

        // TOTP verify
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
            .then(function(j){
                if (j.success) {
                    humanMessage('#fw-verify-result', 'Code accepted. 2FA is working.', 'success');
                } else {
                    humanMessage('#fw-verify-result', 'Invalid code.', 'error');
                }
            });
        });

        // Initial status check (in case a scan just finished)
        pollScanStatus();
    });

})(jQuery);
