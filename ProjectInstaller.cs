using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration.Install;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MeshCentralRouterCmd
{
    [RunInstaller(true)]
    public partial class ProjectInstaller : System.Configuration.Install.Installer
    {
        public ProjectInstaller()
        {
            InitializeComponent();
        }

        public override void Install(IDictionary stateSaver)
        {
            var path = new StringBuilder(Context.Parameters["assemblypath"]);
            if (path[0] != '"') { path.Insert(0, '"'); path.Append('"'); }
            path.Append(" --service");
            Context.Parameters["assemblypath"] = path.ToString();
            base.Install(stateSaver);
        }
    }
}
