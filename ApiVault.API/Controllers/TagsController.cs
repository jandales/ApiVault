using ApiVault.API.Extensions;
using ApiVault.Core.DTOs;
using ApiVault.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ApiVault.API.Controllers;

[ApiController]
[Authorize]
[Route("api/v1/tags")]
public class TagsController(ITagService tags) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Create(TagRequest request)
    {
        var result = await tags.CreateAsync(User.GetUserId(), request);
        return result.Succeeded ? StatusCode(StatusCodes.Status201Created, result.Value) : this.ToProblem(result);
    }

    [HttpGet]
    public async Task<IActionResult> List() => Ok(await tags.ListAsync(User.GetUserId()));

    [HttpPut("{id:guid}")]
    public async Task<IActionResult> Rename(Guid id, TagRequest request)
    {
        var result = await tags.RenameAsync(User.GetUserId(), id, request);
        return result.Succeeded ? Ok(result.Value) : this.ToProblem(result);
    }

    [HttpDelete("{id:guid}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var result = await tags.DeleteAsync(User.GetUserId(), id);
        return result.Succeeded ? NoContent() : this.ToProblem(result);
    }
}
