function DeleteAdmin(email) {
       openCustomPopup('Enter reason for Deleteing '+email + ' : ', function(reason) {
        if (!reason) {
            showToast("Reason cannot be empty", "Error", 0);
            return;
        }

        const data = localStorage.getItem("admindata");
        var adminObject = JSON.parse(data);
        const formData = {
            token: adminObject.token,
            publickey: adminObject.publickey,
            email: email,
            reason: reason // Add reason to formData
        };

        fetch("http://localhost:8080/deleteadmin", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(formData),
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                showToast(data.error.message, "Error", 0);
                return;
            }
            showToast(data.result.message,"Success",3);
           
        })
        .catch(error => {
            showToast(error, "Error", 0);
        });
    });
}
