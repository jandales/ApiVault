using ApiVault.API.Extensions;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiVault.API.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/secrets")]
public class SecretsController(ISecretService secrets) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Create(CreateSecretRequest request)
    {
        var result = await secrets.CreateAsync(User.GetUserId(), request);
        return result.Succeeded
            ? CreatedAtAction(nameof(Get), new { id = result.Value!.Id }, result.Value)
            : this.ToProblem(result);
    }

    [HttpGet]
    public async Task<IActionResult> List([FromQuery] SecretQuery query) =>
        Ok(await secrets.ListAsync(User.GetUserId(), query));

    [HttpGet("{id:guid}")]
    public async Task<IActionResult> Get(Guid id)
    {
        var result = await secrets.GetAsync(User.GetUserId(), id);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Update(Guid id, UpdateSecretRequest request)
    {
        var result = await secrets.UpdateAsync(User.GetUserId(), id, request);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var result = await secrets.DeleteAsync(User.GetUserId(), id);
        return result.Succeeded ? NoContent() : this.ToProblem(result);
    }

    [HttpPost("{id:guid}/archive")]
    public async Task<IActionResult> Archive(Guid id)
    {
        var result = await secrets.SetArchivedAsync(User.GetUserId(), id, true);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpPost("{id:guid}/restore")]
    public async Task<IActionResult> Restore(Guid id)
    {
        var result = await secrets.SetArchivedAsync(User.GetUserId(), id, false);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpGet("{id:guid}/versions")]
    public async Task<IActionResult> GetVersions(Guid id)
    {
        var result = await secrets.GetVersionsAsync(User.GetUserId(), id);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpPost("{id:guid}/versions")]
    public async Task<IActionResult> CreateVersion(Guid id, CreateSecretVersionRequest request)
    {
        var result = await secrets.CreateVersionAsync(User.GetUserId(), id, request);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }
}
