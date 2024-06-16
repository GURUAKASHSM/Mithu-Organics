function DisplayDeveloperAudit() {
    console.log("DisplayDeveloperAudit")
    HideAll()
    
  
    const data = localStorage.getItem("admindata")
    var adminObject = JSON.parse(data);
  
    
    let fromdate = document.getElementById("listdeveloperaudit-fromdate").value
    let todate = document.getElementById("listdeveloperaudit-todate").value
    let searchby = document.getElementById("listdeveloperaudit-searchby").value
    let searchvalue = document.getElementById("listdeveloperaudit-searchvalue").value


    const formData = {
        token: adminObject.token,
        publickey: adminObject.publickey,
        noofdata:Number(document.getElementById("listdeveloperaudit-pagenation").value),
        sortby: document.getElementById("listdeveloperaudit-orderby").value,
        sortorder: Number(document.getElementById("listdeveloperaudit-ordervalue").value),
        status:document.getElementById("listdeveloperaudit-status").value
    }
    if (searchby && searchvalue) {
        formData["searchby"] = searchby
        formData["searchvalue"] = searchvalue
    }
    if (fromdate) {
        formData["fromdate"] = fromdate + "T00:00:00Z";
    }
    if (todate) {
        formData["todate"] = todate + "T00:00:00Z"

    }
    document.getElementById("devauditsnip").style.display = "block";
    console.log(formData)
    fetch("http://localhost:8080/listdeveloperaudit", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify(formData),
    })
        .then(response => response.json())
        .then(data => {
            console.log(data)
            if (data.error) {
                showToast(data.error.message, "Error", 0);
                return
            }
            let html = ""
            document.querySelector('.developeraudit-list-body').innerHTML = html;
            if (!data.result.data) {
                return
            }
     
           
            data.result.data.forEach((audit,index) => {

                html += `

            <tr class="candidates-list">
            <td class="title">
              <div class="candidate-list-details">
                <div class="candidate-list-info">
                  <div class="candidate-list-title customer">
                    <h5 class="mb-0"><a href="#">${audit.errorid}</a></h5>
                  </div>
                  <div class="candidate-list-option">
                    <ul class="list-unstyled">
                      <li><i class="fas fa-filter pr-1"></i>${audit.errortime}</li>
                    </ul>
                  </div>
                </div>
              </div>
            </td>
            <td class="candidate-list-favourite-time text-center"> <a
                class="candidate-list-favourite order-2 text-danger" href="#"></a>
              <span class="candidate-list-time order-1">${audit.message}</span></td>
            </td>

            <td class="candidate-list-favourite-time text-center"> <a
                class="candidate-list-favourite order-2 text-danger" href="#"></a>
              <span class="candidate-list-time order-1">${audit.iscleared ? "FIXED" : "NOT YET FIXED"}</span></td>
            </td>
            <td>
              <ul class="list-unstyled mb-0 d-flex justify-content-end">
        
               <li  onclick="displayObjectInPopup('${encodeURIComponent(JSON.stringify(audit))}')"><a class="text-danger" data-toggle="tooltip" title=""
              data-original-title="Delete"><i class="far fa-eye"></i></a></li>
              
              </ul>
            </td>
          </tr>`;

            });
            
            document.getElementById("noofitemsindeveloperaudit").innerHTML =`${data.result.data.length} of ${data.result.data.length}`
            document.querySelector('.developeraudit-list-body').innerHTML = html;
        })
        .catch(error => {
            showToast(error, "Error", 0);
        });
}

DefaultDeveloperAuditSet()
function DefaultDeveloperAuditSet() {
    document.getElementById("listdeveloperaudit-status").value = "ALL"
    document.getElementById("listdeveloperaudit-fromdate").value = ""
    document.getElementById("listdeveloperaudit-todate").value = ""
    document.getElementById("listdeveloperaudit-searchby").value = ""
    document.getElementById("listdeveloperaudit-searchvalue").value = ""
}



