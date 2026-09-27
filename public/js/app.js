const loginForm = document.getElementById("login-form");
const loginMessage = document.getElementById("login-message");

if (loginForm) {
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const nimInput = document.getElementById("nim");
    const passwordInput = document.getElementById("password");

    const nim = nimInput.value.trim();
    const password = passwordInput.value;

    if (!nim || !password) {
      loginMessage.textContent = "NIM dan password wajib diisi.";
      return;
    }

    loginMessage.textContent = "Sedang login...";

    try {
      const response = await fetch("/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "include",
        body: JSON.stringify({
          nim,
          password
        })
      });

      let data;

      try {
        data = await response.json();
      } catch {
        data = {};
      }

      console.log("Response login:", response.status, data);

      if (!response.ok || !data.success) {
        loginMessage.textContent =
          data.message || "Login gagal. Periksa NIM dan password.";

        return;
      }

      loginMessage.textContent = "Login berhasil. Mengalihkan...";

      console.log("User login:", data.user);

      // Gunakan redirect dari backend
      if (data.redirectUrl) {
        window.location.href = data.redirectUrl;
        return;
      }

      // Fallback kalau backend tidak mengirim redirectUrl
      if (data.user?.role === "praktikan") {
        window.location.href = "/dashboard.html";
      } else if (data.user?.role === "asisten") {
        window.location.href = "/asisten.html";
      } else if (data.user?.role === "admin") {
        window.location.href = "/admin.html";
      } else {
        window.location.href = "/";
      }

    } catch (error) {
      console.error("Error login:", error);

      loginMessage.textContent =
        "Tidak dapat terhubung ke server.";
    }
  });
}