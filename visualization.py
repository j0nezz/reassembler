import numpy as np
import matplotlib.pyplot as plt


__all__ = ['plot_network']



def plot_network(sources_data, middle_layers_data):
    print("Plot network", sources_data, middle_layers_data)
    # Set the random seed for reproducibility
    np.random.seed(0)

    # Create the sources (blue points)
    num_sources = len(sources_data)
    sources_x = np.zeros(num_sources)
    sources_y = np.linspace(0, 1, num_sources)
    sources_sizes = 50  # np.interp(sources_data, (np.min(sources_data), np.max(sources_data)), (50, 200))

    # Create the target (red point)
    target_x = 1
    target_y = 0.5

    # Plot the points
    fig, ax = plt.subplots()
    ax.scatter(sources_x, sources_y, c='blue', s=sources_sizes, alpha=0.75, zorder=10)
    ax.scatter(target_x, target_y, c='red', s=200, alpha=0.75, zorder=10)

    # Plot the middle layers (intermediate nodes)
    num_layers = len(middle_layers_data)
    for layer_idx, layer_data in enumerate(middle_layers_data):
        layer_x = (layer_idx + 1) / (num_layers + 1)
        num_intermediate_nodes = len(layer_data)
        layer_y = np.linspace(0, 1, num_intermediate_nodes)
        layer_sizes = np.interp(layer_data, (np.min(layer_data), np.max(layer_data)), (50, 200))

        # Plot the intermediate nodes with sizes based on the provided data
        ax.scatter(np.full_like(layer_y, layer_x), layer_y, c='black', s=layer_sizes, alpha=0.5, zorder=10)

        # Add the code to plot lines between the layers
        if layer_idx > 0:  # Connect the current layer with the previous layer
            prev_layer_data = middle_layers_data[layer_idx - 1]
            prev_layer_x = (layer_idx) / (num_layers + 1)
            prev_layer_y = np.linspace(0, 1, len(prev_layer_data))
            for prev_point_y in prev_layer_y:
                for point_y in layer_y:
                    plt.plot([prev_layer_x, layer_x], [prev_point_y, point_y], c='gray', alpha=0.3, lw=1)

        # Connect sources to the first layer of intermediate nodes
        if layer_idx == 0:
            for source_y in sources_y:
                for point_y in layer_y:
                    plt.plot([0, layer_x], [source_y, point_y], c='gray', alpha=0.3, lw=1)

        # Connect target to the last layer of intermediate nodes
        if layer_idx == num_layers - 1:
            for point_y in layer_y:
                plt.plot([layer_x, target_x], [point_y, target_y], c='gray', alpha=0.3, lw=1)

    # Set aspect ratio

    ax.set_aspect('equal')
    ax.spines[['right', 'top']].set_visible(False)
    plt.show()

