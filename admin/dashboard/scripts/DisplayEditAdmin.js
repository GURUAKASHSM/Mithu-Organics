function DisplatEditAdmin(event, email) {
    event.preventDefault();
    HideAll()

    const data = localStorage.getItem("admindata");
    var adminObject = JSON.parse(data);
    const formData = {
        token: adminObject.token,
        publickey: adminObject.publickey,
        adminemail: email,
    };

    fetch("http://localhost:8080/viewadmin", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
    })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showToast(data.error.message, "Error", 0)
                return
            }
            console.log(data)
            document.getElementById("inputUsername").value = data.result.adminname
            document.getElementById("inputadminid").value = data.result.adminid
            document.getElementById("inputEmailAddress").value = data.result.email
            document.getElementById("wronginput").value = data.result.wronginput || 0
            document.getElementById("createdtime").value = data.result.createdtime
            document.getElementById("logintime").value = data.result.logintime
            document.getElementById("createdby").value = data.result.createdby
            if ( data.result.canupdate) {
                document.getElementById("canupdate").value = "true"
            } else {
                document.getElementById("canupdate").value = "false"
            }

            if ( data.result.candelete) {
                document.getElementById("candelete").value = "true"
            } else {
                document.getElementById("candelete").value = "false"
            }
            if ( data.result.canalteradmin) {
                document.getElementById("canalteradmin").value = "true"
            } else {
                document.getElementById("canalteradmin").value = "false"
            }
            document.getElementById("displayeditadmin").style.display = "block"

        })
        .catch(error => {
            showToast(error, "Error", 0);
        });

}