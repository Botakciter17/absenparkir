// static/admin.js

(function () {
  // Helpers
  function $(sel, root = document) { return root.querySelector(sel); }
  function $all(sel, root = document) { return Array.from(root.querySelectorAll(sel)); }

  const imageModal = $("#imageModal");
  const exifModal  = $("#exifModal");
  const modalImage = $("#modalImage");
  const exifData   = $("#exifData");

  function openImageModal(src) {
    if (!src) return;
    modalImage.src = src;
    imageModal.classList.add("active");
  }

  function openExifModal(raw) {
    // data-exif dipasang pakai |tojson => string JSON (kutip + escape)
    let text = raw;
    try { text = JSON.parse(raw); } catch (e) { /* biarkan raw apa adanya */ }
    exifData.textContent = text || "(Kosong)";
    exifModal.classList.add("active");
  }

  function closeModal(modal) {
    modal.classList.remove("active");
    if (modal === imageModal) modalImage.src = "";
  }

  // Event delegation setelah DOM siap
  document.addEventListener("DOMContentLoaded", function () {
    // Klik "Lihat Gambar"
    document.body.addEventListener("click", function (e) {
      const a = e.target.closest(".show-image-btn");
      if (a) {
        e.preventDefault();
        const src = a.getAttribute("data-file");
        openImageModal(src);
      }
    });

    // Klik tombol EXIF
    document.body.addEventListener("click", function (e) {
      const b = e.target.closest(".exif-btn");
      if (b) {
        e.preventDefault();
        const raw = b.getAttribute("data-exif") || "";
        openExifModal(raw);
      }
    });

    // Tutup modal via tombol X
    $all(".modal .modal-close").forEach(btn => {
      btn.addEventListener("click", function () {
        const modal = btn.closest(".modal");
        if (modal) closeModal(modal);
      });
    });

    // Tutup modal bila klik area gelap
    $all(".modal").forEach(modal => {
      modal.addEventListener("click", function (e) {
        if (e.target === modal) closeModal(modal);
      });
    });

    // Tutup modal dengan ESC
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") {
        if (imageModal.classList.contains("active")) closeModal(imageModal);
        if (exifModal.classList.contains("active")) closeModal(exifModal);
      }
    });
  });
})();
