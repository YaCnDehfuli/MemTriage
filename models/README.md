# Bundled VADViT checkpoint

`Multi_32_224_6f_3u.pt` is the trained multiclass checkpoint used automatically
by MemTriage's process-analysis workflow. It has a `vit_base_patch32_224` backbone
and a nine-output head. The two binary checkpoints are not part of this workflow.

The checkpoint is tracked with Git LFS. Install Git LFS before cloning, or run
`git lfs pull` in an existing checkout. Docker mounts this directory read-only
in both API and worker. Local Python runs resolve this directory automatically.

`labels.json` supplies the output order from the VADViT paper's multiclass
confusion-matrix legend: Backdoor, Benign, Exploit, HackTool, Hoax, Rootkit,
Trojan, Virus, Worm. This matches the training loader's alphabetical ordering.
Benign is index 1. Classification and attention use the trained weights.

See [model details](../docs/MODEL.md) for configuration and result interpretation.
