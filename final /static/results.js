document.addEventListener("DOMContentLoaded", function () {
    // Hover effect on table rows
    document.querySelectorAll("table tbody tr").forEach(row => {
        row.addEventListener("mouseenter", () => {
            row.style.backgroundColor = "#bbdefb";
        });

        row.addEventListener("mouseleave", () => {
            row.style.backgroundColor = "";
        });
    });
});
