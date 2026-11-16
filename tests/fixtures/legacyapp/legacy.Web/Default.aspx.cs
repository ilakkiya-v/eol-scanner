public partial class _Default : System.Web.UI.Page {
    protected void Page_Load(object sender, EventArgs e) {
        var cmd = new SqlCommand("SELECT * FROM Orders WHERE Id = " + Request.QueryString["id"], conn);
        Response.Write(Request.QueryString["msg"]);
    }
}
