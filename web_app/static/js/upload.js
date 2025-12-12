// web_app/static/js/upload.js
document.addEventListener("DOMContentLoaded", function () {
  const uploadForm = document.getElementById("uploadForm");
  const uploadBtn = document.getElementById("uploadBtn");
  const uploadResult = document.getElementById("uploadResult");
  const uploadProgress = document.getElementById("uploadProgress");
  const progressBar = uploadProgress.querySelector(".progress-bar");
  const progressText = document.getElementById("progressText");

  // Gestion de l'upload
  uploadForm.addEventListener("submit", function (e) {
    e.preventDefault();

    const formData = new FormData(uploadForm);

    // Afficher la progression
    uploadProgress.style.display = "block";
    uploadResult.style.display = "none";
    uploadBtn.disabled = true;

    // Animation de progression (simulée)
    let progress = 0;
    const interval = setInterval(() => {
      progress += 5;
      progressBar.style.width = `${progress}%`;

      if (progress >= 90) {
        clearInterval(interval);
      }
    }, 200);

    // Envoi du fichier
    fetch("/upload", {
      method: "POST",
      body: formData,
    })
      .then((response) => response.json())
      .then((data) => {
        clearInterval(interval);
        progressBar.style.width = "100%";
        progressText.textContent = "Analyse terminée !";

        setTimeout(() => {
          uploadProgress.style.display = "none";
          uploadResult.style.display = "block";
          uploadBtn.disabled = false;

          document.getElementById(
            "resultMessage"
          ).textContent = `Fichier "${data.filename}" analysé avec succès. ${data.alerts} alertes détectées.`;

          // Redirection automatique après 3 secondes
          setTimeout(() => {
            window.location.href = "/alerts";
          }, 3000);
        }, 1000);
      })
      .catch((error) => {
        console.error("Erreur:", error);
        clearInterval(interval);
        uploadProgress.style.display = "none";
        uploadBtn.disabled = false;

        alert("Erreur lors de l'upload: " + error.message);
      });
  });

  // Exemples de test
  document.querySelectorAll(".test-example").forEach((btn) => {
    btn.addEventListener("click", function () {
      const exampleType = this.dataset.example;

      // Crée un fichier de test selon le type
      let content = "";
      let filename = "";

      switch (exampleType) {
        case "ssh":
          filename = "ssh_example.log";
          content = `Jan 15 10:30:22 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:30:23 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:30:24 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:30:25 server sshd[1234]: Accepted password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:31:00 server sshd[1235]: Invalid user hacker from 10.0.0.1 port 1234`;
          break;

        case "web":
          filename = "web_example.log";
          content = `192.168.1.100 - - [15/Jan/2024:10:30:22 +0100] "GET /index.php?id=1 UNION SELECT * FROM users" 200 1234
192.168.1.101 - - [15/Jan/2024:10:31:00 +0100] "GET /index.php?q=<script>alert('xss')</script>" 200 456
192.168.1.102 - - [15/Jan/2024:10:32:00 +0100] "GET /admin/login.php" 200 234
192.168.1.102 - - [15/Jan/2024:10:32:01 +0100] "GET /admin/admin.php" 200 345
192.168.1.102 - - [15/Jan/2024:10:32:02 +0100] "GET /admin/setup.php" 200 456`;
          break;

        case "windows":
          filename = "windows_example.evtx";
          content = `Windows Event Log Example - Simulated data
Security ID: SYSTEM
Account Name: ADMIN$
Client Address: 192.168.1.100
Logon Type: 3
Logon Process: NtLmSsp
Failure Reason: Unknown user name or bad password`;
          break;
      }

      // Crée un blob et un objet File
      const blob = new Blob([content], { type: "text/plain" });
      const file = new File([blob], filename, { type: "text/plain" });

      // Met à jour le formulaire
      const dataTransfer = new DataTransfer();
      dataTransfer.items.add(file);
      document.getElementById("logfile").files = dataTransfer.files;

      // Définit le type de log
      document.getElementById("log_type").value = exampleType;

      // Soumet automatiquement
      uploadForm.requestSubmit();
    });
  });

  // Génération de rapport
  document
    .getElementById("generateReportBtn")
    ?.addEventListener("click", function () {
      const type = prompt("Type de rapport (html/json):", "html");

      if (type === "html" || type === "json") {
        window.open(`/api/report/generate?type=${type}`, "_blank");
      }
    });
});
