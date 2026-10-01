/* ═══════════════════════════════════════════════════════════════════════════
   CyberLens AI — Client-side JavaScript
   ═══════════════════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {

    // ── Auto-dismiss flash messages ──────────────────────────────────────
    setTimeout(() => {
        document.querySelectorAll('.flash').forEach(el => {
            el.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            el.style.opacity = '0';
            el.style.transform = 'translateY(-8px)';
            setTimeout(() => el.remove(), 400);
        });
    }, 5000);


    // ── File Upload (AJAX with progress) ─────────────────────────────────
    const dropZone    = document.getElementById('dropZone');
    const fileInput   = document.getElementById('fileInput');
    const uploadForm  = document.getElementById('uploadForm');
    const uploadStatus= document.getElementById('uploadStatus');
    const uploadError = document.getElementById('uploadError');
    const progressBar = document.getElementById('progressBar');
    const uploadFileName = document.getElementById('uploadFileName');
    const uploadFileSize = document.getElementById('uploadFileSize');

    if (dropZone && fileInput) {
        // Click to browse
        dropZone.addEventListener('click', () => fileInput.click());

        // Drag & drop
        dropZone.addEventListener('dragover', e => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('dragover');
        });
        dropZone.addEventListener('drop', e => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                handleFileSelected(e.dataTransfer.files[0]);
            }
        });

        // Manual selection
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length) handleFileSelected(fileInput.files[0]);
        });
    }

    function handleFileSelected(file) {
        // Client-side validation: 20 MB
        const MAX_SIZE = 20 * 1024 * 1024;
        if (file.size > MAX_SIZE) {
            showUploadError(`File too large (${formatSize(file.size)}). Maximum allowed: 20 MB.`);
            return;
        }

        // Check extension
        const ext = file.name.split('.').pop().toLowerCase();
        if (!['csv', 'xlsx', 'log'].includes(ext)) {
            showUploadError('Invalid file type. Allowed: .csv, .xlsx, .log');
            return;
        }

        // Show file info
        if (uploadFileName) uploadFileName.textContent = file.name;
        if (uploadFileSize) uploadFileSize.textContent = formatSize(file.size);
        if (uploadStatus)   uploadStatus.classList.add('active');
        if (uploadError)    uploadError.classList.remove('active');

        // Upload via AJAX
        uploadFile(file);
    }

    function uploadFile(file) {
        const formData = new FormData();
        formData.append('file', file);

        const xhr = new XMLHttpRequest();
        xhr.open('POST', '/upload', true);

        // Progress
        xhr.upload.addEventListener('progress', e => {
            if (e.lengthComputable && progressBar) {
                const pct = Math.round((e.loaded / e.total) * 100);
                progressBar.style.width = pct + '%';
            }
        });

        xhr.onload = () => {
            if (progressBar) {
                progressBar.style.width = '100%';
                progressBar.classList.add('complete');
            }

            try {
                const resp = JSON.parse(xhr.responseText);
                if (xhr.status === 200 && resp.success) {
                    setTimeout(() => {
                        window.location.href = resp.redirect;
                    }, 600);
                } else {
                    showUploadError(resp.error || 'Upload failed');
                }
            } catch {
                showUploadError('Unexpected server response');
            }
        };

        xhr.onerror = () => showUploadError('Network error during upload');
        xhr.send(formData);
    }

    function showUploadError(msg) {
        if (uploadError) {
            uploadError.textContent = msg;
            uploadError.classList.add('active');
        }
        if (uploadStatus) uploadStatus.classList.remove('active');
    }


    // ── Analyze button (POST + loading overlay) ──────────────────────────
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loadingOverlay = document.getElementById('loadingOverlay');

    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', e => {
            e.preventDefault();
            if (loadingOverlay) loadingOverlay.classList.add('active');

            fetch('/analyze', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        window.location.href = data.redirect;
                    } else {
                        if (loadingOverlay) loadingOverlay.classList.remove('active');
                        alert('Analysis failed: ' + (data.error || 'Unknown error'));
                    }
                })
                .catch(err => {
                    if (loadingOverlay) loadingOverlay.classList.remove('active');
                    alert('Analysis error: ' + err.message);
                });
        });
    }


    // ── Chart.js — Dashboard charts ──────────────────────────────────────
    const pieCanvas = document.getElementById('categoryPieChart');
    const barCanvas = document.getElementById('severityBarChart');

    if ((pieCanvas || barCanvas) && typeof Chart !== 'undefined') {
        fetch('/api/stats')
            .then(r => r.json())
            .then(data => {
                if (pieCanvas && data.category_distribution) {
                    renderPieChart(pieCanvas, data.category_distribution);
                }
                if (barCanvas && data.severity_distribution) {
                    renderBarChart(barCanvas, data.severity_distribution);
                }
            })
            .catch(() => {});
    }

    function renderPieChart(canvas, dist) {
        const labels = Object.keys(dist);
        const values = Object.values(dist);
        const colors = [
            '#ef4444', '#3b82f6', '#f59e0b', '#8b5cf6',
            '#06b6d4', '#10b981', '#ec4899',
        ];

        new Chart(canvas, {
            type: 'doughnut',
            data: {
                labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors.slice(0, labels.length),
                    borderColor: 'rgba(10,14,26,0.8)',
                    borderWidth: 2,
                    hoverOffset: 8,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#94a3b8',
                            font: { family: "'Inter', sans-serif", size: 12 },
                            padding: 16,
                            usePointStyle: true,
                            pointStyleWidth: 10,
                        },
                    },
                    title: {
                        display: true,
                        text: 'Attack Category Distribution',
                        color: '#f1f5f9',
                        font: { family: "'Inter', sans-serif", size: 15, weight: 600 },
                        padding: { bottom: 16 },
                    },
                },
            },
        });
    }

    function renderBarChart(canvas, dist) {
        const order = ['Critical', 'High', 'Medium', 'Low'];
        const labels = order.filter(s => dist[s] !== undefined);
        const values = labels.map(s => dist[s] || 0);
        const colors = {
            Critical: '#dc2626',
            High:     '#ef4444',
            Medium:   '#f59e0b',
            Low:      '#10b981',
        };

        new Chart(canvas, {
            type: 'bar',
            data: {
                labels,
                datasets: [{
                    label: 'Count',
                    data: values,
                    backgroundColor: labels.map(l => colors[l] || '#3b82f6'),
                    borderRadius: 6,
                    borderSkipped: false,
                    barThickness: 48,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false },
                    title: {
                        display: true,
                        text: 'Severity Distribution',
                        color: '#f1f5f9',
                        font: { family: "'Inter', sans-serif", size: 15, weight: 600 },
                        padding: { bottom: 16 },
                    },
                },
                scales: {
                    x: {
                        ticks: { color: '#94a3b8', font: { size: 12 } },
                        grid:  { display: false },
                    },
                    y: {
                        beginAtZero: true,
                        ticks: {
                            color: '#94a3b8',
                            font: { size: 12 },
                            stepSize: 1,
                        },
                        grid: { color: 'rgba(148,163,184,0.08)' },
                    },
                },
            },
        });
    }


    // ── Utilities ────────────────────────────────────────────────────────
    function formatSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / 1048576).toFixed(1) + ' MB';
    }
});
