function ResetPassword(event,email){
    event.preventDefault();
    openCustomPopup('Enter reason for Reseting Password of '+email + ' : ', function(reason) {
        if (!reason) {
            showToast("Reason cannot be empty", "Error", 0);
            return;
        }

        const data = localStorage.getItem("admindata")
        var adminObject = JSON.parse(data);
         const formData = {
            token:adminObject.token,
            publickey:adminObject.publickey,
            adminemail:email,
            reason:reason,
         }
    
         fetch("http://localhost:8080/resetpassword", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(formData),
        })
            .then(response => response.json())
            .then(data => {
                if(data.error){
                    showToast(data.error.message,"Error",0)
                    return
                }
                showToast(data.result.message,"Success",3)
                 
            })
            .catch(error => {
                showToast(error, "Error", 0);
            });

    });
}