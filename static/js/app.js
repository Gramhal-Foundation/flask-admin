function redirectToChartPage() {
  window.location.href = "/chart";
}

function openModal() {
  var modal = document.getElementById("createUserModal");
  modal.classList.remove("hidden");
}

function closeModal() {
  var modal = document.getElementById("createUserModal");
  modal.classList.add("hidden");
}

document.getElementById("myForm").addEventListener("submit", function (event) {
  event.preventDefault();

  var formData = new FormData(event.target);

  fetch("/submit", {
    method: "POST",
    body: formData,
  })
    .then((response) => response.text())
    .then((data) => {
      console.log(data);
    })
    .catch((error) => {
      console.error("Error:", error);
    });

  closeModal();
});

document.getElementById("itemId").click(function () {
  var itemId = $(this).data("item-id");
  alert(itemId);
});
