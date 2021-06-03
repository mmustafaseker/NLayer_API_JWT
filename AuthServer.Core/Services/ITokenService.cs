using AuthServer.Core.Configuration;
using AuthServer.Core.DTO_s;
using AuthServer.Core.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AuthServer.Core.Services
{
    public interface ITokenService
    {
        TokenDto CreateToken(UserApp userApp);
        ClientTokenDto CreateClientToken(Client client);
    }
}
