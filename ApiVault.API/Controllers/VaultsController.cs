using ApiVault.API.Extensions;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiVault.API.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/vaults")]
/// <summary>
/// Single-vault model: the account's vault is created at registration (/auth/register) and lives as long as the
/// account, so there are no create or delete endpoints here.
/// </summary>
public class VaultsController(IVaultService vaults) : ControllerBase
{
    [HttpGet]
    public async Task<IActionResult> List([FromQuery] int page = 1, [FromQuery] int pageSize = 25) =>
        Ok(await vaults.ListAsync(User.GetUserId(), page, pageSize));

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
    {
        var result = await vaults.GetAsync(User.GetUserId(), id);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateVaultRequest request)
    {
        var result = await vaults.UpdateAsync(User.GetUserId(), id, request);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpGet("{id:guid}/key-wrappers")]
    public async Task<IActionResult> GetKeyWrappers(Guid id)
    {
        var result = await vaults.GetWrappersAsync(User.GetUserId(), id);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpPost("{id:guid}/key-wrappers")]
    public async Task<IActionResult> UpsertKeyWrapper(Guid id, KeyWrapperRequest request)
    {
        var result = await vaults.UpsertWrapperAsync(User.GetUserId(), id, request, HttpContext.GetClientContext());
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }
}
